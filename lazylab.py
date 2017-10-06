#!/usr/bin/env python3
#
#
import os, sys
import hashlib, re, subprocess as sp, shlex
import requests, time
import shutil
import hmac

# sample subset size
sample_size = 20
# virus total API key
apikey_vt = ""
# metascan API key
apikey_md = ""
#totalhash API key
apikey_th = ""
# hybrid-analysis API
apikey_ha =	""
secret_ha =	""

class RequestAdapt:
  def __init__(self):
    self.count = 0
  def get(self, *args, **kwargs):
    if self.count == 3:
      print("[*] Cooling off for API limits (60s)...")
      time.sleep(60)
      self.count = 0
      return requests.get(*args, **kwargs)
    else:
      self.count = self.count + 1
      return requests.get(*args, **kwargs)

def md5sum(fname):
  hash_md5 = hashlib.md5()
  with open(fname, "rb") as f:
    for chunk in iter(lambda: f.read(4096), b""): 
      hash_md5.update(chunk)
  return hash_md5.hexdigest()
  
def sha1sum(fname):
  hash_sha1 = hashlib.sha1()
  with open(fname, "rb") as f:
    for chunk in iter(lambda: f.read(4096), b""):
      hash_sha1.update(chunk)
  return hash_sha1.hexdigest()
  
def sha256sum(fname):
  hash_sha256 = hashlib.sha256()
  with open(fname, "rb") as f:
    for chunk in iter(lambda: f.read(4096), b""):
      hash_sha256.update(chunk)
  return hash_sha256.hexdigest()

def get_my_hashes(rootpath, code):
  if os.path.exists("match.txt"):
    print("[*] Found match.txt file!\nRunning this function again will overwrite your previous matches!")
    choice = input(" Do you want to continue? [y/n](y) : ")
    if not choice=='' or not choice=='y':
      print("Aborting!")
      sys.exit(1)
      
  print("[*] Calculating hashes for files and saving all to hashes.txt...", end=" ")
  out_all = open("hashes.txt", "w+")
  
  # lets dive in
  for path, subs, files in os.walk(rootpath):
    for name in files:
      p = os.path.join(path, name)
      h = md5sum(p)
      out_all.write("{} {}\n".format(p, h))
  out_all.close()
  print("Done!")
      
  print("[*] Shuffling all hashes to get a nice mix of samples...", end=" ")
  args = shlex.split("shuf --output=shuf.txt hashes.txt")
  proc = sp.Popen(args)
  proc.wait()
  print("Done!")
  
  print("[*] Saving code matching hashes in match.txt", end=" ")
  count = 0
  out_match = open("match.txt", "w+")
  with open("shuf.txt") as out_shuf:
    for line in out_shuf:
      if count < sample_size:
        p, h = line.split()
        if re.search(code, h):
          s = "{} {} {} {}\n".format(p, h, sha1sum(p), sha256sum(p))
          out_match.write(s)
          count = count + 1
          print("{}".format(count), end=" ")
      else:
        break
  print("Done!")

def api_virustotal():
  global apikey_vt
  reqcount = 0
  path_dir = "virustotal"
  print("[*] Checking md5 hashes on Virustotal...")
  if not os.path.exists(path_dir):
    os.makedirs(path_dir)
  r = RequestAdapt()
  with open("match.txt") as out_with:
    for line in out_with:
      p, md5, sha1, sha256 = line.split()
      params = {'apikey': apikey_vt, 'resource': md5}
      response = r.get("https://www.virustotal.com/vtapi/v2/file/report", params = params)
      print(response)
      out_virii = open(os.path.join(path_dir,"{}.txt".format(md5)), "w+")
      out_virii.write("File: {}\n{}".format(p,response.json()))
      out_virii.close()
  print("[*] Done!")

def hash_patch():
  out_fest = open("patch.txt", "w+")
  print("[*] Save matching hashes in patch.txt (md5, sha1 and sha256)...", end=" ")
  with open("match.txt") as out_match:
    for line in out_match:
      p, h = line.split()
      s = "{} {} {} {}\n".format(p, h, sha1sum(p), sha256sum(p))
      out_fest.write(s)
  out_fest.close()
  print("Done!")

def gather():
  print("[*] Copying samples into samples directory...", end=" ")
  if not os.path.exists("samples"):
    os.makedirs("samples")
  with open("match.txt") as f:
    for line in f:
      p, md5, sha1, sha256 = line.split()
      shutil.copy(p, os.path.join("samples", md5))
  print("Done!")

def api_metadefender():
  path_dir = "metadefender" 
  print("[*] Checking hashes on Metadefender...")
  if not os.path.exists(path_dir):
    os.makedirs(path_dir)  
  headers = {"apikey":apikey_md}
  with open("match.txt") as in_match:
    for line in in_match:
      p, md5, sha1, sha256 = line.split()
      params = {"hash_value":sha256}
      out_api = open(os.path.join(path_dir, "{}.txt".format(md5)),"w+")
      result = requests.get("https://api.metadefender.com/v2/hash/{}".format(sha256), headers=headers, params=params)
      print(result)
      out_api.write("File: {}\n{}".format(p,result.json()))
      out_api.close()
  print("Done!")

def api_totalhash():
  path_dir = "totalhash" 
  print("[*] Checking hashes on #totalhash...")
  if not os.path.exists(path_dir):
    os.makedirs(path_dir)  
  # this API is very picky, lets play anyway
  userid = "ccase"
  with open("match.txt") as in_match:
    for line in in_match:
      p, md5, sha1, sha256 = line.split()
      query = "hash:{}".format(sha1)
      hash_hmac = hmac.new(apikey_th.encode(), digestmod=hashlib.sha256, msg=query.encode())
      sign = hash_hmac.hexdigest()
      out_api = open(os.path.join(path_dir, "{}.txt".format(md5)),"w+")
      result = requests.get("https://api.totalhash.com/search/{}&id={}&sign={}".format(query,userid,sign))
      print(result)
      out_api.write("File: {}\nURL: {}\n{}".format(p,"https://totalhash.cymru.com/analysis/?{}".format(sha1),result.text))
      out_api.close()
  print("Done!")

def patch_match():
  patch_dir = os.path.join(os.getcwd(),"samples")
  out_patch = open("patch.txt", "w+")
  print("[*] Patching match.txt...", end = " ")
  with open("match.txt") as in_match:
    for line in in_match:
      p, md5, sha1, sha256 = line.split()
      out_patch.write("{} {} {} {}\n".format(os.path.join(patch_dir, md5), md5, sha1, sha256))
  out_patch.close()
  print("Done!")

def get_filetype():
  out_ftype = open("types.txt","w+")
  print("[*] Analyzing filetypes...")
  with open("match.txt") as in_match:
    for line in in_match:
      p, md5, sha1, sha256 = line.split()
      args = shlex.split("file -b {}".format(p))
      cmd_out = sp.check_output(args).decode()
      out = "{} {}".format(p, cmd_out)
      print(out)
      out_ftype.write(out)
  print("Done!")

def api_hybrid():
  path_dir = "hybrid" 
  print("[*] Checking hashes on hybrid-analysis...")
  if not os.path.exists(path_dir):
    os.makedirs(path_dir)
  req_adapt = RequestAdapt()
  with open("match.txt") as in_match:
    for line in in_match:
      p, md5, sha1, sha256 = line.split()
      out_api = open(os.path.join(path_dir, "{}.txt".format(md5)),"w+")
      params = {'apikey': apikey_ha, 'secret': secret_ha}
      headers = {'User-agent': 'VxStream Sandbox'}
      result = req_adapt.get("https://www.hybrid-analysis.com/api/scan/{}".format(sha256), params=params, headers=headers)
      print(result)
      out_api.write("File: {}\n{}".format(p,result.text))
      out_api.close()
  print("Done!") 

def strings():
  print("[*] Checking for interesting strings...")
  path_dir = "strings"
  interesting = [".dll", ".so", "lib", ".onion", "http", "https", "Get", "Set", "Ex", ".exe", "Load", "WS"]
  if not os.path.exists(path_dir):
    os.makedirs(path_dir)
  with open("match.txt") as in_match:
    for line in in_match:
      p, md5, sha1, sha256 = line.split()
      out_str = open(os.path.join(path_dir, "{}.txt".format(md5)), "w+")
      for lex in interesting:
        lookup = re.compile(lex)
        args = shlex.split("strings {}".format(p))
        cmd_out = sp.check_output(args).decode()
        steps = cmd_out.split("\n")
        for step in steps:
          found = lookup.search(step)
          if found:
            print(step)
            out_str.write("{}\n".format(step))
  print("Done!")

def pe_is(missing="n"):
  print("[*] Running PE analysis on executables...", end=" ")
  path_dir = "pescan"
  if not os.path.exists(path_dir):
    os.makedirs(path_dir)
  with open("types.txt") as in_types:
    for line in in_types:
      split = line.split()
      p, rest = (split[:1][0], split[1:])
      if "executable" in rest:
        out_exec = open(os.path.join(path_dir, "{}.txt".format(p[29:])), "w+")
        args = shlex.split("pescan -v {}".format(p))
        try:
          cmd_out = sp.check_output(args).decode()
        except Exception as e:
          print("[*] pescan error: {}".format(str(e)))
          print("Continuing...")
        out_exec.write(cmd_out)
        args = shlex.split("readpe {}".format(p))
        try:
          cmd_out = sp.check_output(args).decode()
        except Exception as e:
          print("[*] readpe error: {}".format(str(e)))
          print("Continuing...")
        out_exec.write(cmd_out)
  print("Done!")

def swag():
  print("Malware Lab3 Lazy Script by Cj")
  print(">> work smart not hard <<\n")
  
def rtfm():
  print("Usage: {} <path> <code>".format(sys.argv[0]))
  sys.exit(1)
  
swag()

if len(sys.argv) != 3:
  rtfm()

def work_hard_for_me_kthxbai():
  # You can tweak what you want the script to do for you here
  get_my_hashes(sys.argv[1], sys.argv[2]) # get sample_size hashes that match your code
  gather()                                # copy to CWD
  api_virustotal()                        # Virustotal API
  api_metadefender()                      # Metadefender API
  api_totalhash()                         # totalhash API
  api_hybrid()                            # Hybrid Analysis API
  get_filetype()                          # Analyze malware filetype
  strings()                               # Check interesting strings
  pe_is()                                 # PE Analysis with PEV

work_hard_for_me_kthxbai()
