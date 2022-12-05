import requests
import socket
import hashlib
import queue
import sys
import json
import threading


q = queue.Queue()

'''
MIST Module is a easy to use module that gives you useful tools you can use in your scripts.

'''
def typeHash(word, hash_mode):
	'''
	Hashes the specific word.

	'''
	word = word.strip()
	try:
		hashed_word = getattr(hashlib, hash_mode)(word.encode()).hexdigest()
		return hashed_word
	except:
		print("Specify a valid hash mode.")
		exit()


class color:
	PURPLE = '\033[95m'
	CYAN = '\033[96m'
	DARKCYAN = '\033[36m'
	BLUE = '\033[94m'
	GREEN = '\033[92m'
	YELLOW = '\033[93m'
	RED = '\033[91m'
	BOLD = '\033[1m'
	UNDERLINE = '\033[4m'
	END = '\033[0m'


class mist:
	def portscan(self, target, begin, end, threads):
		print("Exit when you need.")
		thread_list = []
		translatePort = {
				20:'ftp',
				21:'ftp',
				22:'ssh',
				25:'smtp',
				53:'dns',
				69:'tftp',
				80:'http',
				88:'Kerberos',
				102:'Iso-tsap',
				110:'POP3',
				123:'ntp',
				135:'Microsoft-EPMAP',
				137:'netBIOS-ns',
				139:'netBIOS-ssn',
				179:'bgp',
				443:'https',
				445:'microsoft-ds',
				512:'exec',
				514:'shell',
				1099:'rmiregistry',
				1524:'ingreslock',
				500:'ISAKMP',
				902:'VMware-Server',
				1725:'steam',
				2049:'nsf',
				2121:'ccproxy-ftp',
				3306:'mySql',
				5432:'postgresql',
				3398:'RDP',
				4664:'Google-Desktop',
				5900:'vnc',
				6000:'X11',
				6667:'irc',
				6681:'BitTorrent',
				6999:'BitTorrent',
				8009:'ajp13',
				8180:'unknown',
				12345:'NetBus',
				18006:'Back Orifice',
				27374:'Sub7'

			}

		portList = []

		for i in range(begin, end+1):
			portList.append(i)

		for port in portList:
			q.put(port)

		def scan(target_ip, port_number):
			try:
				s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				s.connect((target_ip, port_number))
				return True
			except:
				return False

		def workers():
			while not q.empty():
				port = q.get()
				if scan(target, port):
					for key, value in translatePort.items():
						if str(key) == str(port):
							print(color.BOLD + color.GREEN + f"Port {port} | {value} | OPEN" + color.END)
							if q.empty():
								q.task_done()
								exit()
		try:
			for i in range(threads):
				t = threading.Thread(target=workers, daemon=True)
				thread_list.append(t)

			for i in range(threads):
				thread_list[i].start()

			for i in range(threads):
				thread_list[i].join()

		except KeyboardInterrupt:
			sys.exit("\n Exiting Scan.")
			




	def hash_crack(self, hashing_t, hash_value, wordlist):
		words_list = open(wordlist).readlines()
		for word in words_list:
			striped_word = word.strip()
			hash_w = typeHash(striped_word, hashing_t)
			if hash_w == hash_value:
				print(striped_word)
				exit()
		print("Hash could not be recognized.")

	def ip_osint(self, target_ip):
		r = requests.get(f"http://ip-api.com/json/{target_ip}")
		results = r.text
		json_results = json.loads(results)
		print(f'''

IP - {target_ip}
Country - {json_results["country"]}
Region Name - {json_results["regionName"]}
City - {json_results["city"]}
ZIP - {json_results["zip"]}
Latitude - {json_results["lat"]}
Longtitude - {json_results["lon"]}
Timezone - {json_results["timezone"]}
ISP - {json_results["isp"]}


			''')
		exit()

	



