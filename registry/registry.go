package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"unicode"

	// thanks, go-digest...
	_ "crypto/sha256"
	_ "crypto/sha512"

	"github.com/docker-library/bashbrew/architecture"

	"github.com/containerd/containerd/images"
	"github.com/containerd/containerd/reference/docker"
	"github.com/containerd/containerd/remotes"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

type ResolvedObject struct {
	Desc ocispec.Descriptor

	ImageRef string
	resolver remotes.Resolver
	fetcher  remotes.Fetcher
}

type resolvedObjectReader struct {
	io.Reader
	c func() error
}

func (r resolvedObjectReader) Close() error {
	if r.c != nil {
		return r.c()
	}
	return nil
}

// Raw returns the raw bytes of the given object with no parsing/processing (but with digest/size verification, including eating any leftover whitespace if left unread; so be sure to eat everything if you don't want Close to error)
func (obj ResolvedObject) Raw(ctx context.Context) (io.ReadCloser, error) {
	// prevent go-digest panics later
	if err := obj.Desc.Digest.Validate(); err != nil {
		return nil, err
	}

	// (perhaps use a containerd content store?? they do validation of all content they ingest, and then there's a cache)

	r, err := obj.fetcher.Fetch(ctx, obj.Desc)
	if err != nil {
		return nil, err
	}
	// defer r.Close() // needs to be part of our ReadCloser -- see below (needs to be part of any error returns below this too, if there are any)

	// make sure we can't possibly read (much) more than we're supposed to
	limited := &io.LimitedReader{
		R: r,
		N: obj.Desc.Size + 1, // +1 to allow us to detect if we read too much (see verification below)
	}

	// copy all read data into the digest verifier so we can validate afterwards
	verifier := obj.Desc.Digest.Verifier()
	tee := io.TeeReader(limited, verifier)

	ret := resolvedObjectReader{
		Reader: tee,
	}
	ret.c = func() error {
		ret.c = nil     // to make sure we don't invoke this close method more than once
		defer r.Close() // just to make sure it happens for sure

		// read anything leftover ...
		bs, err := io.ReadAll(tee)
		if err != nil {
			return err
		}
		// ... and make sure it was just whitespace, if anything
		// TODO this should probably stream in batches instead of blindly doing "ReadAll" (could be a pretty obscene amount of whitespace and ReadAll reads in 512 byte batches anyhow)
		for _, b := range bs {
			if !unicode.IsSpace(rune(b)) {
				return fmt.Errorf("unexpected non-whitespace at the end of %q: %+v\n", obj.Desc.Digest.String(), rune(b))
			}
		}

		// after reading *everything*, we should have exactly one byte left in our LimitedReader (anything else is an error)
		if limited.N < 1 {
			return fmt.Errorf("size of %q is bigger than it should be (%d)", obj.Desc.Digest.String(), obj.Desc.Size)
		} else if limited.N > 1 {
			return fmt.Errorf("size of %q is %d bytes smaller than it should be (%d)", obj.Desc.Digest.String(), limited.N-1, obj.Desc.Size)
		}

		// and finally, let's verify our checksum
		if !verifier.Verified() {
			return fmt.Errorf("digest of %q not correct", obj.Desc.Digest.String())
		}

		return r.Close()
	}
	return ret, nil
}

func (obj ResolvedObject) fetchJSON(ctx context.Context, v interface{}) error {
	r, err := obj.Raw(ctx)
	if err != nil {
		return err
	}
	defer r.Close() // just in case / to be absolutely sure

	// decode directly! (mostly avoids double memory hit for big objects)
	// (TODO protect against malicious objects somehow?)
	if err := json.NewDecoder(r).Decode(v); err != nil {
		return err
	}

	if err := r.Close(); err != nil {
		return err
	}

	return nil
}

func get[T any](ctx context.Context, obj ResolvedObject) (*T, error) {
	var ret T
	if err := obj.fetchJSON(ctx, &ret); err != nil {
		return nil, err
	}
	return &ret, nil
}

// At returns a new object pointing to the given descriptor (still within the context of the same repository as the original resolved object)
func (obj ResolvedObject) At(desc ocispec.Descriptor) *ResolvedObject {
	obj.Desc = desc
	return &obj
}

// Index assumes the given object is an "index" or "manifest list" and fetches/returns the parsed index JSON
func (obj ResolvedObject) Index(ctx context.Context) (*ocispec.Index, error) {
	if !obj.IsImageIndex() {
		return nil, fmt.Errorf("unknown media type: %q", obj.Desc.MediaType)
	}
	return get[ocispec.Index](ctx, obj)
}

// Manifests returns a list of "content descriptors" that corresponds to either this object (if it is a single-image manifest) or all the manifests of the index/manifest list this object represents
func (obj ResolvedObject) Manifests(ctx context.Context) ([]ocispec.Descriptor, error) {
	if obj.IsImageManifest() {
		return []ocispec.Descriptor{obj.Desc}, nil
	}
	index, err := obj.Index(ctx)
	if err != nil {
		return nil, err
	}
	return index.Manifests, nil
}

// Architectures returns a map of "bashbrew architecture" strings to a list of members of the object (as either a manifest or an index) which match the given "bashbrew architecture" (either in an explicit "platform" object or by reading all the way down into the image "config" object for the platform fields)
func (obj ResolvedObject) Architectures(ctx context.Context) (map[string][]ResolvedObject, error) {
	manifests, err := obj.Manifests(ctx)
	if err != nil {
		return nil, err
	}

	ret := map[string][]ResolvedObject{}
	for _, manifestDesc := range manifests {
		obj := obj.At(manifestDesc)

		if obj.Desc.Platform == nil || obj.Desc.Platform.OS == "" || obj.Desc.Platform.Architecture == "" {
			manifest, err := obj.Manifest(ctx)
			if err != nil {
				return nil, err // TODO should we really return this, or should we ignore it?
			}
			config, err := obj.At(manifest.Config).ConfigBlob(ctx)
			if err != nil {
				return nil, err // TODO should we really return this, or should we ignore it?
			}
			obj.Desc.Platform = &config.Platform
		}

		objPlat := architecture.Normalize(*obj.Desc.Platform)
		obj.Desc.Platform = &objPlat

		for arch, plat := range architecture.SupportedArches {
			if plat.Is(architecture.OCIPlatform(objPlat)) {
				ret[arch] = append(ret[arch], *obj)
			}
		}
	}
	return ret, nil
}

// Manifest assumes the given object is a (single-image) "manifest" (see [ResolvedObject.At]) and fetches/returns the parsed manifest JSON
func (obj ResolvedObject) Manifest(ctx context.Context) (*ocispec.Manifest, error) {
	if !obj.IsImageManifest() {
		return nil, fmt.Errorf("unknown media type: %q", obj.Desc.MediaType)
	}
	return get[ocispec.Manifest](ctx, obj)
}

// ConfigBlob assumes the given object is a "config" blob (see [ResolvedObject.At]) and fetches/returns the parsed config object
func (obj ResolvedObject) ConfigBlob(ctx context.Context) (*ocispec.Image, error) {
	if !images.IsConfigType(obj.Desc.MediaType) {
		return nil, fmt.Errorf("unknown media type: %q", obj.Desc.MediaType)
	}
	return get[ocispec.Image](ctx, obj)
}

func (obj ResolvedObject) IsImageManifest() bool {
	return images.IsManifestType(obj.Desc.MediaType)
}

func (obj ResolvedObject) IsImageIndex() bool {
	return images.IsIndexType(obj.Desc.MediaType)
}

// Resolve returns an object which can be used to query a registry for manifest objects or certain blobs with type checking helpers
func Resolve(ctx context.Context, image string) (*ResolvedObject, error) {
	var (
		obj = ResolvedObject{
			ImageRef: image,
		}
		err error
	)

	ref, err := docker.ParseAnyReference(obj.ImageRef)
	if err != nil {
		return nil, err
	}
	if namedRef, ok := ref.(docker.Named); ok {
		// add ":latest" if necessary
		namedRef = docker.TagNameOnly(namedRef)
		ref = namedRef
	}
	obj.ImageRef = ref.String()

	obj.resolver = NewDockerAuthResolver()

	obj.ImageRef, obj.Desc, err = obj.resolver.Resolve(ctx, obj.ImageRef)
	if err != nil {
		return nil, err
	}

	obj.fetcher, err = obj.resolver.Fetcher(ctx, obj.ImageRef)
	if err != nil {
		return nil, err
	}

	return &obj, nil
}
