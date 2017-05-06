'''
******************************************************************************************************
Project Name:		Security Threat Intelligence Get Alerts
Purpose:		Retrieves news articles from security sources and parses them out in one script
File Name:		getalerts.py
Language:		Python
Author:			Derek P. Arnold
Original Date:		12-26-2013
Revision History:	12-26-2013 Created
                        05-06-2017 Moved log files to base directory, moved config to config directory
******************************************************************************************************
'''

#getalerts.py
#get US CERT alerts and parse them out
from xml.dom import minidom
from datetime import datetime, timedelta
from time import gmtime, strftime

###download xml
import urllib2
import re


import os
import subprocess

# Edit directory names here if appropriate
if os.name == 'nt':
    ## Full path to your Splunk installation
    splunk_home = 'C:\Program Files\Splunk'
    ## Full path to python executable
    python_bin = 'C:\Program Files (x86)\Python-2.7-32bit\python.exe'
else:
    ## Full path to your Splunk installation
    # For some reason:
    #splunk_home = '/appl/opt/splunk_fwd/'
    # For a sensible OS:
    splunk_home = '/opt/splunk'

    ## Full path to python executable
    # For Mac OS X:
    #python_bin = '/Library/Frameworks/Python.framework/Versions/2.7/bin/python'
    # For a sensible filesystem:
    python_bin = '/usr/bin/python'

urlfile_name_txt = "news_urls.conf"

urlfile_name =  os.path.join(splunk_home, 'etc', 'apps', 'optiv_TA_threat', 'config', urlfile_name_txt)


urlList = []
titleList = []
pubDateList = []
linkList = []
descList = []
#urlFile = open("/opt/splunk/etc/apps/optiv_threat_intel/bin/url.txt",'r')
urlFile = open(urlfile_name,'r')
#urlFile = open("./url.txt",'r')


logfile_name_end = "getalerts" + strftime("%m-%d-%Y-%H-%M-%S", gmtime()) + ".log"

logfile_name =  os.path.join(splunk_home, 'etc', 'apps', 'optiv_TA_threat', 'logs', logfile_name_end)

script_version = "3.22"

f = open(logfile_name,'w')

def main():

   print '[*] Script Started at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT\n'

   print '[*] Script version: ' + script_version

# for loop to iterate through the sources
   for url in urlFile.readlines():
      url = url.strip('\n')
      print "[*] Checking URL: " + url
      numStories=5
      iter=1
      req = urllib2.Request(url, headers={'User-Agent' : "Mozilla/5.0 (Windows NT 6.2; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/32.0.1667.0 Safari/537.36"})
      usock = urllib2.urlopen(req)
      xmldoc = minidom.parse(usock)
      for element in xmldoc.getElementsByTagName('title'):
	if (iter<=numStories):
	   #print "APPENDING: " + element.firstChild.nodeValue
	   if element.firstChild:
            titleList.append(element.firstChild.nodeValue.encode('utf-8').strip())
	iter=iter+1
      iter=1
      for element in xmldoc.getElementsByTagName('pubDate'):
	if (iter<=numStories):
	   #print "APPENDING: " + element.firstChild.nodeValue
	   if element.firstChild:
               pubDateList.append(element.firstChild.nodeValue.encode('utf-8').strip())
	iter=iter+1
      iter=1
      for element in xmldoc.getElementsByTagName('link'):
	if (iter<=numStories):
	   #print "APPENDING: " + element.firstChild.nodeValue
	   if element.firstChild:
             linkList.append(element.firstChild.nodeValue.encode('utf-8').strip())
	iter=iter+1
      iter=1
      for element in xmldoc.getElementsByTagName('description'):
	if (iter<=numStories):
	   #print "APPENDING: " + element.firstChild.nodeValue
           if element.firstChild:
               longDesc = element.firstChild.nodeValue.encode('utf-8').strip()
               #shortDesc = longDesc[:238] + (longDesc[238:] and '...')
               #re.sub(r'<.+?>', '', longDesc,10)
               longDesc=re.sub(r'<.*?>', '', longDesc,50)
               longDesc=re.sub(r'&nbsp;', '', longDesc,50)
               longDesc=re.sub('&#(\d+);', '', longDesc,50)
               #p = re.compile(r'<.*?>')
               shortDesc = longDesc[:1000] + (longDesc[1000:] and '...')
               #shortDesc = shortDesc.strip('\"')
	       #shortDesc = dequote(shortDesc)
	       shortDesc = shortDesc.replace('"', '').strip()
               descList.append(shortDesc)
	iter=iter+1
      iter=1
   #print "ENTERING PRINT FUNCTION!!"
   for y in range(0, len(titleList)):
	  #then = datetime.now () - timedelta (hours = 72)
	  #now = pubDateList[y].toD
		  #if (now - then) < timedelta (hours = 72):
        #print "y: " + str(y) + " len(titleList): " + str(len(titleList)) + " len(descList): " + str(len(descList))

	if (y <= len(pubDateList)):
           #print "y: " + str(y) + "len pubdatelist: " + str(len(pubDateList)) + "pubdatelist: " + str(pubDateList)
	   print "publish_date=\"" + pubDateList[y] + "\""
           f.write('publish_date=\"' + pubDateList[y] + '\"\n')
        print "title=\"" + titleList[y] + "\""
        f.write('title=\"' + titleList[y] + '\"\n')
	if (y <= len(linkList)):
	   print "url=" + linkList[y]
           f.write('url=' + linkList[y] + '\n')
        #if (y <= len(descList) and descList[y] != None
        if (y <= len(descList)) :
            try:
               print "desc=\"" + descList[y].strip('\n') + "\"\n"
               f.write('desc=\"' + descList[y].strip('\n')  + '\"\n')
            except IndexError:
               print "desc=blank\n"
               f.write("desc=blank\n")
	#print "************************************************************************"
        #f.write('************************************************************************\n')

#f.close()

if __name__ == '__main__':
	main()
