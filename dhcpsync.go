package main

import (
    "crypto/tls"
    "crypto/x509"
    "flag"
    "log"
    "net/http"
    "io/ioutil"
)

func getDhcpLeases(w http.ResponseWriter, r *http.Request) {
    f, err := ioutil.ReadFile("/var/lib/dhcp/dhcpd.leases")
    if err != nil {
        log.Print(err)
        http.Error(w, "An error has occurred.", http.StatusInternalServerError)
        return
    }
    w.Write(f)
}

func PopulateCertPool(s string) (*x509.CertPool, error) {
    certBytes, err := ioutil.ReadFile(s)
    certPool := x509.NewCertPool()
    certPool.AppendCertsFromPEM(certBytes)
    return certPool, err
}

func main() {
    caCert := flag.String("ca", "ca.crt", "Path to CA cert used for validating client certificates")
    serverCert := flag.String("cert", "server.crt", "Path to public cert used for serving TLS")
    serverKey := flag.String("key", "server.key", "Path to private key used for serving TLS")
    serverPort := flag.String("port", "15443", "Port to use")
    flag.Parse()

    caCertPool, e := PopulateCertPool(*caCert)
    if e != nil {
        log.Fatal(e)
    }

    tlsConfig := &tls.Config {
        ClientAuth: tls.RequireAndVerifyClientCert,
        ClientCAs: caCertPool,
        MinVersion: tls.VersionTLS12,
    }
    tlsConfig.BuildNameToCertificate()

    httpServer := &http.Server {
        Addr: ":" + *serverPort,
        TLSConfig: tlsConfig,
    }

    log.Print("Starting HTTPS file server on port ", *serverPort)
    http.HandleFunc("/leases", getDhcpLeases)
    err := httpServer.ListenAndServeTLS(*serverCert, *serverKey)
    if err != nil {
        log.Fatal(err)
    }
}
