package main

import (
	"fmt"
	"html/template"
	"net/http"
	"os"
	"strconv"

	"github.com/musobarlab/rsax"
)

const (
	DefaultPort = 8999
)

func main() {

	// key, err := rsax.GenerateKey(rsax.DefaultKeySize)
	// if err != nil {
	// 	fmt.Println(err)
	// 	os.Exit(1)
	// }

	// fmt.Println(string(key.PublicKeyBytes))

	// privateKey, err := rsax.ParseRSAPrivateKeyFromHex([]byte(key.GetPrivateKeyHexStr()))
	// if err != nil {
	// 	fmt.Println(err)
	// 	os.Exit(1)
	// }

	// publicKey, err := rsax.ParseRSAPublicKeyFromHex([]byte(key.GetPublicKeyHexStr()))
	// if err != nil {
	// 	fmt.Println(err)
	// 	os.Exit(1)
	// }

	// message := []byte("This is a test!")

	// cipertText, err := rsax.EncryptWithOAEPToBase64Str(message, publicKey)
	// if err != nil {
	// 	fmt.Println(err)
	// 	os.Exit(1)
	// }

	// signature, err := rsax.SignWithPSS(cipertText, privateKey)
	// if err != nil {
	// 	fmt.Println(err)
	// 	os.Exit(1)
	// }

	// err = rsax.VerifyWithPSS(cipertText, signature, publicKey)
	// if err != nil {
	// 	fmt.Println("signature invalid")
	// } else {
	// 	fmt.Println("signature valid")
	// }

	// plainText, err := rsax.DecryptWithOAEPFromBase64Str(string(cipertText), privateKey)
	// if err != nil {
	// 	fmt.Println(err)
	// 	os.Exit(1)
	// }

	// fmt.Println(string(cipertText))

	// fmt.Println(string(plainText))
	var port uint16
	portStr := os.Getenv("HTTP_PORT")
	if portStr != "" {
		p, err := strconv.Atoi(portStr)
		if err != nil {
			port = uint16(DefaultPort)
		} else {
			port = uint16(p)
		}
	} else {
		port = uint16(DefaultPort)
	}

	generatorKeyHTMLTemplate, err := template.New("generatePage").Parse(Page)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	http.HandleFunc("/", generateKeyHandler(generatorKeyHTMLTemplate))

	fmt.Printf("webapp running on port :%d\n", port)
	err = http.ListenAndServe(fmt.Sprintf(":%d", port), nil)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

const (
	Page = `<!DOCTYPE html>
	<html>
	<head>
	  <meta charset="utf-8">
	  <meta name="viewport" content="width=device-width">
	  <meta charset="utf-8">
	  <meta name="viewport" content="width=device-width, initial-scale=1">
	  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-1BmE4kWBq78iYhFldvKuhfTAU6auU8tT94WrHftjDbrCEXSU1oBoqyl2QvZ6jIW3" crossorigin="anonymous">
	  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js" integrity="sha384-ka7Sk0Gln4gmtz2MlQnikT1wXgYsOg+OMhuP+IlRH9sENBO0LRn5q+8nbTov4+1p" crossorigin="anonymous"></script>
	  <title>Generate RSA Private and Public Key</title>
	</head>
	<body>
	  
	  <nav class="navbar navbar-dark bg-dark">
		<div class="container-fluid">
		  <a class="navbar-brand">Generate RSA Private and Public Key</a>
		</div>
	  </nav>
	
	  <div class="container mt-4">
		<form action="/" method="POST">
		  <div class="mb-3 row">
			<label class="col-sm-2 col-form-label" for="keySize">Size</label>
			<div class="col-sm-10">
			  <select class="form-select" name="keySize" id="keySize">
				<option value="1024">1024</option>
				<option value="2048">2048</option>
				<option value="4096">4096</option>
			  </select>
			 </div>
		  </div>
		  <div class="mb-3 row">
			<div class="col-sm-10">
			  <button type="submit" class="btn btn-primary">Generate</button>
			 </div>
		   </div>
		</form>
		
		{{if .Generated}}
		  <label class="col-sm-2 col-form-label" for="keySize">RSA Private Key</label>
		  <div class="form-floating">
			<textarea class="form-control" name="rsaPrivateKey" id="floatingTextarea2" style="height: 200px">{{.RsaPrivateKey}}</textarea>
		  </div>
	
		  <label class="col-sm-2 col-form-label" for="keySize">RSA Public Key</label>
		  <div class="form-floating">
			<textarea class="form-control" name="rsaPrivateKey" id="floatingTextarea2" style="height: 200px">{{.RsaPublicKey}}</textarea>
		  </div>
		{{end}}
	  </div>
	  
	</option>
	</body>
	</html>`
)

func generateKeyHandler(t *template.Template) http.HandlerFunc {
	return func(res http.ResponseWriter, req *http.Request) {
		data := struct {
			Generated     bool
			RsaPrivateKey string
			RsaPublicKey  string
		}{
			Generated:     false,
			RsaPrivateKey: "",
			RsaPublicKey:  "",
		}

		if req.Method == "GET" {
			t.Execute(res, data)
		} else {

			keySizeStr := req.FormValue("keySize")

			keySize, err := strconv.ParseUint(keySizeStr, 10, 32)
			if err != nil {
				t.Execute(res, data)
				return
			}

			key, err := rsax.GenerateKey(int(keySize))
			if err != nil {
				t.Execute(res, data)
				return
			}

			data.RsaPrivateKey = string(key.PrivateKeyBytes)
			data.RsaPublicKey = string(key.PublicKeyBytes)
			data.Generated = true

			t.Execute(res, data)
		}
	}
}
