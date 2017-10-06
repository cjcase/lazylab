# lazylab
A python script to do batch static analysis on suspected malware (created for Lab3 of ITC8120 Course at TUT)

# Requirements
You will need:
* Python3
* PEV https://github.com/merces/pev
* GNU Tools (file, strings)

*Hint: Kali Linux has all this by default* 

# Usage
1. Get you API Keys for the different services the script will use
  * VirusTotal https://developers.virustotal.com/v2.0/reference
  * Metadefender https://www.metadefender.com/public-api/#!/about
  * TotalHash https://totalhash.cymru.com/contact-us/
  * Hybrid Analysis https://www.hybrid-analysis.com/apikeys/info
2. Add your keys to the script
3. Tweak the amount of files you want to do analysis on (variable in the script)
4. Run the script by pointing it to a directory and specifing a 2 number code to choose malware samples from
`python3 lazylab.py /path/to/malwares 42`

# To Do
Needless to say, this is a quick and dirty approach and as such, the script was made quickly and rather dirty.
Some ideas for improvement:
* Actually create a report at the end from all gathered information (WiP)
* If a hash is not found in the APIs, upload file for analysis
* Better output organization (i.e. file grouping, changing to directory-per-sample)
* Add more APIs (YES, Cuckoo Sandbox instances have a RESTful API)

# Contributing
Feel like helping? a beer is cool but pull requests are way cooler, fork the repo, fix or add a thing and become a contributor!
Testing and reporting bugs is also greatly appreciated.

Made with <3 for my cybersec classmates
