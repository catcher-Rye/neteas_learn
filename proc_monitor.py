import os
import time
import socket
import argparse
import psutil
import time
import logging
from prettytable import PrettyTable

def get_host_info(timeout):
	try:
		time.clock()		

		print ("host info:")
		try:
			s = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
			s.connect(('192.168.133.142',80))
			ip = s.getsockname()[0]
			hostinfo = socket.gethostbyaddr(ip)
			hostname = hostinfo[0]
		finally:
			s.close()

		if time.clock() > timeout:
			hostname = "unknown"
			raise Exception("EXCEPTION : the process timeout!!!")
	except Exception ,e :
		print e

	return ip,hostname

def setLogger(log):
	logging.basicConfig(level=logging.DEBUG,
				format='%(asctime)s %(filename)s[line:%(lineno)d] %(levelname)s %(message)s',
				datefmt='%a, %d %b %Y %H:%M:%S',
				filename='proc_monitor.log',
				filemode='w')
	logging.debug(log)

def get_process_need():
	print ("proc info:")
	outputFile = open('output_info'+'.log','a+')

	pidList = psutil.pids()
	count=0
	x = PrettyTable(["username", "pid", "cmdline", "vms","rss","pcpu","pmem"])
	x.align["username"] = "l"
	x.padding_width = 1

	for pid in pidList:
		p = psutil.Process(pid)
		rss,vms = p.memory_info()		
		
		if count == args.limit:
			break
		elif p.exe() != "":
			x.add_row([p.username(),pid,p.cmdline(),vms,rss,p.cpu_percent(),p.memory_percent()])
			log = p.username() + "," + str(pid) + "," + str(p.cmdline()) + "," + str(vms) + "," + str(rss) + "," + str(p.cpu_percent()) + "," + str(p.memory_percent())
			setLogger(log)
			count += 1

	print x.get_string(sortby=args.sort, reversesort=bool(args.direction))
	outputFile.write(str(x))
	outputFile.write('\n********************************************\n')
	  
	outputFile.close()

def get_parameter():
	parser = argparse.ArgumentParser()
	parser.add_argument("-s","--sort", help="sort the infomation by the field",default="pcpu")
	parser.add_argument("-d","--direction", help="sort the informaiton by desc or asce",default=True)
	parser.add_argument("-l","--limit", help="choose the number of the process",type=int,default=5)
	parser.add_argument("-v","--version", help="dispaly the version of this script",action='version',version='%(prog)s 1.0')
	args = parser.parse_args()
	return args

if __name__ == '__main__':
	args = get_parameter()
	
	try:
		ip,hostname = get_host_info(3)
		print ip,hostname
	except Exception as e:
		print('your process of get hostname is timeout: ', e)
	
	print ("\n")
	get_process_need()