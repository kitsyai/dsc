// Command dsc signs with a digital signature certificate (DSC) on a USB
// token, for web pages, through the hey local hub. It never sees a private
// key: the token or the OS key store signs, after the user confirms each
// signature in a native dialog.
//
//	dsc serve --port 7451 [--pkcs11 /path/to/driver.so]...
//	dsc list  [--pkcs11 /path/to/driver.so]...
//	dsc version
package main

import (
	"context"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/kitsyai/dsc/internal/server"
)

// version is set at build time (-ldflags "-X main.version=...").
var version = "dev"

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

func usage() {
	fmt.Fprint(os.Stderr, `dsc - sign with a USB token DSC for web pages, through hey

Usage:
  dsc serve --port <port> [--pkcs11 <driver library>]...
  dsc list [--pkcs11 <driver library>]...
  dsc version

Usually started by hey:  hey up dsc

On macOS and Linux, dsc looks for common token drivers; add yours with
--pkcs11 or DSC_PKCS11_MODULES (path list). On Windows it uses the
certificates your token driver puts in the Personal certificate store.
`)
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = serve(os.Args[2:])
	case "list":
		err = list(os.Args[2:])
	case "version", "--version", "-v":
		fmt.Println("dsc", version)
	case "help", "--help", "-h":
		usage()
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "dsc:", err)
		os.Exit(1)
	}
}

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	port := fs.Int("port", 0, "loopback port to listen on")
	var modules multiFlag
	fs.Var(&modules, "pkcs11", "PKCS#11 driver library (repeatable)")
	fs.Parse(args)
	if *port <= 0 || *port > 65535 {
		return errors.New("--port is required")
	}
	store, err := openStore(modules)
	if err != nil {
		return err
	}
	defer store.Close()

	ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(*port)))
	if err != nil {
		return err
	}
	api := &server.Server{Store: store, Version: version, Port: *port}
	srv := &http.Server{
		Handler:           api.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		// No WriteTimeout: /sign waits for the user at the dialog.
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(shutdown)
	}()
	fmt.Fprintf(os.Stderr, "dsc %s listening on 127.0.0.1:%d\n", version, *port)
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func list(args []string) error {
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	var modules multiFlag
	fs.Var(&modules, "pkcs11", "PKCS#11 driver library (repeatable)")
	fs.Parse(args)
	store, err := openStore(modules)
	if err != nil {
		return err
	}
	defer store.Close()
	certs, err := store.List()
	if err != nil {
		return err
	}
	if len(certs) == 0 {
		fmt.Println("No signing certificates found. Is the token plugged in and its driver installed?")
		return nil
	}
	for _, c := range certs {
		cert, err := x509.ParseCertificate(c.DER)
		if err != nil {
			continue
		}
		fmt.Printf("%s  %s  (issued by %s, valid until %s)  [%s]\n", c.ID[:12], cert.Subject.CommonName,
			cert.Issuer.CommonName, cert.NotAfter.Format("2006-01-02"), c.Label)
	}
	return nil
}
