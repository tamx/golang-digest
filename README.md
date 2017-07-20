# golang-digest

This code can authorize Digest authentication on GAE enviroment.
The example code is below.

    package center

    import (
      "fmt"
      "net/http"

      "github.com/tamx/golang-digest"
      "google.golang.org/appengine"
      "google.golang.org/appengine/log"
    )

    func init() {
      http.HandleFunc("/",
        digest.NewDigestAuth(CheckPassword, Logger).HandleFunc)
    }

    func CheckPassword(username string) string {
      if username == "tam" {
        return "test"
      }
      return ""
    }

    func Logger(w http.ResponseWriter, r *http.Request) {
      ctx := appengine.NewContext(r)
      log.Infof(ctx, "Requested URL: %v", r.URL)
      fmt.Fprintf(w, "Hello.")
    }
