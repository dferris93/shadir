package main

import (
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"flag"
	"fmt"
	"hash"
	"hash/crc32"
	"hash/crc64"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"syscall"

	"github.com/jzelinskie/whirlpool"
	"github.com/zeebo/blake3"
	"github.com/zeebo/xxh3"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/sha3"
	"golang.org/x/sync/errgroup"
)

type hardLinkKey struct {
	dev uint64
	ino uint64
}

type hardLinkResult struct {
	hash  string
	err   error
	ready chan struct{}
}

type hardLinkTracker struct {
	links sync.Map
}

func newHardLinkKey(info fs.FileInfo) (hardLinkKey, bool) {
	stat, inodeOk := info.Sys().(*syscall.Stat_t)
	if !inodeOk || stat.Nlink <= 1 {
		return hardLinkKey{}, false
	}
	return hardLinkKey{dev: uint64(stat.Dev), ino: stat.Ino}, true
}

func (h *hardLinkTracker) claim(info fs.FileInfo) (*hardLinkResult, bool) {
	key, ok := newHardLinkKey(info)
	if !ok {
		return nil, true
	}

	result := &hardLinkResult{ready: make(chan struct{})}
	actual, loaded := h.links.LoadOrStore(key, result)
	if loaded {
		return actual.(*hardLinkResult), false
	}
	return result, true
}

func (r *hardLinkResult) finish(hash string, err error) {
	r.hash = hash
	r.err = err
	close(r.ready)
}

func (r *hardLinkResult) print(path string) error {
	<-r.ready
	if r.err != nil {
		return r.err
	}
	fmt.Printf("%s  %s  *\n", r.hash, path)
	return nil
}

func newHasher(hashalgo string) hash.Hash {
	switch hashalgo {
	case "crc32":
		return crc32.NewIEEE()
	case "crc64":
		return crc64.New(crc64.MakeTable(crc64.ISO))
	case "md5":
		return md5.New()
	case "sha1":
		return sha1.New()
	case "sha256":
		return sha256.New()
	case "sha512":
		return sha512.New()
	case "sha3-512":
		return sha3.New512()
	case "sha3-256":
		return sha3.New256()
	case "shake128-256":
		return sha3.NewShake128()
	case "shake256-512":
		return sha3.NewShake256()
	case "blake2b-512":
		hasher, _ := blake2b.New512(nil)
		return hasher
	case "blake2b-256":
		hasher, _ := blake2b.New256(nil)
		return hasher
	case "whirlpool":
		return whirlpool.New()
	case "blake3":
		return blake3.New()
	case "xxh3-64":
		return xxh3.New()
	case "xxh3-128":
		return xxh3.New128()
	default:
		fmt.Fprintf(os.Stderr, "unsupported hash algorithm %s falling back to sha256", hashalgo)
		return sha256.New()
	}
}

func hashFile(path, hashalgo string) (string, error) {
	hasher := newHasher(hashalgo)
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", hasher.Sum(nil)), nil
}

func worker(path string, hardLinks *hardLinkTracker, info fs.FileInfo, hashalgo string) error {
	result, owner := hardLinks.claim(info)
	if !owner {
		return result.print(path)
	}

	hash, err := hashFile(path, hashalgo)
	if result != nil {
		result.finish(hash, err)
	}
	if err != nil {
		return err
	}

	fmt.Printf("%s  %s  -\n", hash, path)
	return nil
}

func checkSymlink(path string) (bool, string, error) {
	fileInfo, err := os.Lstat(path)
	if err != nil {
		return false, "", err
	}
	if fileInfo.Mode()&os.ModeSymlink != 0 {
		target, err := os.Readlink(path)
		if err != nil {
			return false, "", err
		}
		return true, target, nil
	}
	return false, "", nil
}

func walkDirectory(dir string, eg *errgroup.Group, followSymlinks bool, hashalgo string, excludePattern *regexp.Regexp) uint64 {
	hardLinks := new(hardLinkTracker)
	filecount := uint64(0)

	filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			fmt.Fprintf(os.Stderr, "unable to walk %s: %v\n", path, err)
			return nil
		}
		if info.IsDir() {
			if excludePattern != nil && excludePattern.MatchString(path) {
				return filepath.SkipDir
			} else {
				return nil
			}
		}

		if excludePattern != nil && excludePattern.MatchString(path) {
			return nil
		}

		if info.Mode().IsRegular() {
			filecount++
			eg.Go(func() error {
				return worker(path, hardLinks, info, hashalgo)
			})
			return nil
		}

		if followSymlinks {
			isSymlink, target, err := checkSymlink(path)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error reading symlink %s: %v\n", path, err)
				return nil
			}
			if isSymlink {
				filecount++
				eg.Go(func() error {
					return worker(target, hardLinks, info, hashalgo)
				})
			}
		} else {
			fmt.Fprintf(os.Stderr, "skipping non-regular file %s\n", path)
		}
		return nil
	})
	return filecount
}

func main() {
	dir := flag.String("dir", ".", "directory to process")
	poolSize := flag.Int("poolsize", 8, "number of workers")
	followSymlinks := flag.Bool("follow-symlinks", false, "follow symlinks")
	hashalgo := flag.String("hash", "sha256", "hash algorithm.  Choices are crc32, crc64, md5, sha1, sha256, sha512, sha3-512, sha3-256, shake128-256, shake256-512, blake2b-512, blake2b-256, whirlpool, blake3, xxh3-64, xxh3-128")
	exclude := flag.String("exclude", "", "exclude files matching this regex pattern")
	flag.Parse()

	var excludePattern *regexp.Regexp
	var err error

	if *exclude != "" {
		excludePattern, err = regexp.Compile(*exclude)
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid exclude pattern: %v\n", err)
			os.Exit(1)
		}
	} else {
		excludePattern = nil
	}

	eg, _ := errgroup.WithContext(context.Background())

	if *poolSize > 0 {
		eg.SetLimit(*poolSize)
	}

	absPath, err := filepath.Abs(filepath.Clean(*dir))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	filecount := walkDirectory(absPath, eg, *followSymlinks, *hashalgo, excludePattern)

	err = eg.Wait()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "Files processed: %d\n", filecount)
}
