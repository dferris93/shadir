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
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/sha3"
	"golang.org/x/sync/errgroup"
)

func worker(path string, hardLinks *sync.Map, info fs.FileInfo, hashalgo string) error {
	var inode uint64
	stat, inodeOk := info.Sys().(*syscall.Stat_t)
	if inodeOk {
		inode = stat.Ino
		h, ok := hardLinks.Load(inode)
		if ok {
			fmt.Printf("%s  %s  *\n", h, path)
			return nil
		}
	}

	var hasher hash.Hash

	switch hashalgo {
	case "crc32":
		hasher = crc32.NewIEEE()
	case "crc64":
		hasher = crc64.New(crc64.MakeTable(crc64.ISO))
	case "md5":
		hasher = md5.New()
	case "sha1":
		hasher = sha1.New()
	case "sha256":
		hasher = sha256.New()
	case "sha512":
		hasher = sha512.New()
	case "sha3-512":
		hasher = sha3.New512()
	case "sha3-256":
		hasher = sha3.New256()
	case "blake2b-512":
		hasher, _ = blake2b.New512(nil)
	case "blake2b-256":
		hasher, _ = blake2b.New256(nil)
	case "whirlpool":
		hasher = whirlpool.New()
	default:
		fmt.Fprintf(os.Stderr, "unsupported hash algorithm %s falling back to sha256", hashalgo)
		hasher = sha256.New()
	}

	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err := io.Copy(hasher, file); err != nil {
		return err
	}
	_ = hasher.Sum(nil)
	hash := hasher.Sum(nil)
	if inodeOk {
		if stat.Nlink > 1 {
			hardLinks.Store(inode, fmt.Sprintf("%x", hash))
		}
	}
	fmt.Printf("%x  %s  -\n", hash, path)
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
	hardLinks := new(sync.Map)
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
	hashalgo := flag.String("hash", "sha256", "hash algorithm.  Choices are crc32, crc64, md5, sha1, sha256, sha512, sha3-512, sha3-256, blake2b-512, blake2b-256, whirlpool")
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
