# golang-digest

This code can authorize Digest authentication on GAE enviroment.
The example code is below.

http.client example:

    client := digest.NewDigestAuthClient(new(http.Client), "tam", "test")
	resp, _ := client.Get("http://www.google.co.jp/")
	byteArray, _ := ioutil.ReadAll(resp.Body)
	fmt.Println(string(byteArray))

urlfetch example:

    c := appengine.NewContext(r)
    client := digest.NewDigestAuthClient(urlfetch.Client(c), "tam", "test")
	resp, _ := client.Get("http://www.google.co.jp/")
	byteArray, _ := ioutil.ReadAll(resp.Body)
	fmt.Println(string(byteArray))

GAE server example:

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
        digest.HandleFunc(CheckPassword, Logger))
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
