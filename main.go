package main

import (
	"bytes"
	"fmt"
	"gopkg.in/ini.v1"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/gen2brain/beeep"
	"github.com/schollz/progressbar/v2"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
)

func gpg_pubkey_encrypt(s, key,passphrase string,isSymmetric bool) string {
	if isSymmetric{
		buf := new(bytes.Buffer)
		msg, _ := armor.Encode(buf, "PGP MESSAGE", nil)
		gpg, _ := openpgp.SymmetricallyEncrypt(msg, []byte(passphrase), nil, nil)
		fmt.Fprintf(gpg, s)
		gpg.Close()
		msg.Close()
		return buf.String()
	}else{
		buf := new(bytes.Buffer)
		msg, _ := armor.Encode(buf, "PGP MESSAGE", nil)
		pubkey, _ := openpgp.ReadArmoredKeyRing(bytes.NewBufferString(key))
		gpg, _ := openpgp.Encrypt(msg, pubkey, nil, nil, nil)
		fmt.Fprintf(gpg, s)
		gpg.Close()
		msg.Close()
		return buf.String()
	}
}

func gpg_pubkey_decrypt(s, publicKey,privateKey,passphrase string,isSymmetric bool) string {
	if isSymmetric {
		passphraseByte := []byte(passphrase)
		dec := []byte(s);
		decbuf := bytes.NewBuffer(dec)
		armorBlock, err := armor.Decode(decbuf)
		if err != nil {
			fmt.Println(err)
			return "err0"
		}
		md, err := openpgp.ReadMessage(armorBlock.Body, nil, func(keys []openpgp.Key, symmetric bool) ([]byte, error) {
			return passphraseByte,nil
		}, nil)
		if err != nil {
			fmt.Println(err)
			return "err1"
		}
		bytes, err := ioutil.ReadAll(md.UnverifiedBody)
		if err != nil {
			fmt.Println(err)
			return "err2"
		}
		decStr := string(bytes)
		return decStr
	}
	var entity *openpgp.Entity
	var entityList openpgp.EntityList
	entityList, _ = openpgp.ReadArmoredKeyRing(bytes.NewBufferString(privateKey))
	entity = entityList[0]
	passphraseByte := []byte(passphrase)
	entity.PrivateKey.Decrypt(passphraseByte)
	for _, subkey := range entity.Subkeys {
		subkey.PrivateKey.Decrypt(passphraseByte)
	}
	dec := []byte(s);
	//dec, err := base64.StdEncoding.DecodeString(s)
	/*if err != nil {
		fmt.Println(err)
		return "err0"
	}*/
	decbuf := bytes.NewBuffer(dec)
	armorBlock, err := armor.Decode(decbuf)
	if err != nil {
		fmt.Println(err)
		return "err0"
	}
	md, err := openpgp.ReadMessage(armorBlock.Body, entityList, nil, nil)
	if err != nil {
		fmt.Println(err)
		return "err1"
	}
	bytes, err := ioutil.ReadAll(md.UnverifiedBody)
	if err != nil {
		fmt.Println(err)
		return "err2"
	}
	decStr := string(bytes)
	return decStr
}
func Exists(name string) bool {
	if _, err := os.Stat(name); err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}
	return true
}
func main() {
	//fmt.Println(gpg_pubkey_encrypt("床前明月光，疑是地上霜。\n举头望明月，低头思故乡。", publicKey))
	if len(os.Args)<2{
		err := beeep.Alert("error", "need args like (gpgtool (-e|-encrypt)/(-d|-decrypt))", "assets/warning.png")
		if err != nil {
			panic(err)
		}
		fmt.Printf("need args like (gpgtool (-e|-encrypt)/(-d|-decrypt))")
		os.Exit(1)
	}
	eNum:=0
	dNum:=0
	sum:=0
	isDecrypt:=os.Args[1] == "-d" || os.Args[1] == "-decrypt"
	filename:=filepath.Base(os.Args[0])
	filedir:=filepath.Dir(os.Args[0])
	cfg, err := ini.Load(filedir+"/gpgtool.ini")
	if err != nil {
		err := beeep.Alert("error", "not find gpgtool.ini", "assets/warning.png")
		if err != nil {
			panic(err)
		}
		fmt.Printf("Fail to read file: %v", err)
		os.Exit(1)
	}
	target:=cfg.Section("config").Key("target").String()
	isSymmetric:=cfg.Section("config").Key("isSymmetric").MustBool(false)
	publicKey:=cfg.Section("config").Key("publicKey").String()
	privateKey:=cfg.Section("config").Key("privateKey").String()
	pass:=cfg.Section("config").Key("passphrase").String()
	ignorePattern:=cfg.Section("config").Key("ignorePattern").String()
	absPath:=target;
	if !filepath.IsAbs(target) {
		os.Chdir(filedir)
		absPath,_ = filepath.Abs(target);
	}

	if !Exists(absPath){
		err := beeep.Alert("error", "target path not exist", "assets/warning.png")
		if err != nil {
			panic(err)
		}
		fmt.Printf("target path not exist")
		return;
	}
	//fmt.Println(os.Args[0],"##",filename,"##",filedir)
	pat := ignorePattern
	pat = pat + "|("+filename+")"
	err = filepath.Walk(absPath,
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if !info.IsDir() {
				r,_ :=regexp.MatchString(pat, path)
				//fmt.Println(r)
				if !r {
					//content, err := ioutil.ReadFile(path)
					//if err != nil {
					//	log.Fatal(err)
					//}else{
						//text := string(content)
						sum++
						/*if  !strings.Contains(text,"-----BEGIN PGP MESSAGE-----"){
							eNum++
							ioutil.WriteFile(path, []byte(gpg_pubkey_encrypt(text, publicKey)), 0644)
						}else{
							dNum++
							ioutil.WriteFile(path, []byte(gpg_pubkey_decrypt(text, publicKey,privateKey,pass)), 0644)
						}*/
					//}
				}
				//fmt.Println(path, r)//,info.Size()
			}
			return nil
		})
	bar := progressbar.New(sum)
	err = filepath.Walk(absPath,
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if !info.IsDir() {
				r,_ :=regexp.MatchString(pat, path)
				//fmt.Println(r)
				if !r {
					content, err := ioutil.ReadFile(path)
					if err != nil {
						log.Fatal(err)
					}else{
						text := string(content)
						if isDecrypt {
							if strings.Contains(text,"-----BEGIN PGP MESSAGE-----") {
								dNum++
								rt:=gpg_pubkey_decrypt(text, publicKey,privateKey,pass,isSymmetric)
								if !strings.HasPrefix(rt,"err") {
									ioutil.WriteFile(path, []byte(rt), 0644)
								}
							}
						}else{
							if  !strings.Contains(text,"-----BEGIN PGP MESSAGE-----"){
								eNum++
								ioutil.WriteFile(path, []byte(gpg_pubkey_encrypt(text, publicKey,pass,isSymmetric)), 0644)
							}
						}
						/*if  !strings.Contains(text,"-----BEGIN PGP MESSAGE-----"){
							eNum++
							ioutil.WriteFile(path, []byte(gpg_pubkey_encrypt(text, publicKey,pass,isSymmetric)), 0644)
						}else{
							dNum++
							rt:=gpg_pubkey_decrypt(text, publicKey,privateKey,pass,isSymmetric)
							if !strings.HasPrefix(rt,"err") {
								ioutil.WriteFile(path, []byte(rt), 0644)
							}
						}*/
						bar.Add(1)
					}
				}
				//fmt.Println(path, r)//,info.Size()
			}
			return nil
		})
	note := "encrypt success!"
	if isDecrypt {
		note = "decrypt success!"
	}
	err = beeep.Notify("info", note, "assets/information.png")
	if err != nil {
		panic(err)
	}
	if err != nil {
		log.Println(err)
	}
}
//-ldflags -H=windowsgui
