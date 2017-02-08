#!/usr/bin/python

##########################################################################################################################
##
##          Script:         optiv_threat_lists.py
##
##          Language:       Python
##
##          Version:        3.25
##
##          Original Date:  05-02-2015
##
##          Author:         Derek Arnold
##
##          Company:        Optiv Security
##
##          Purpose:        Gathers various IPs from open source threat lists and parses them into a Splunk-friendly key/value pair format.
##
##          Syntax:         python ./optiv_threat_lists.py
##
##          Copyright (C):  2015 Derek Arnold (ransomvik)
##
##          License:        This program is free software: you can redistribute it and/or modify
##                          it under the terms of the GNU General Public License as published by
##                          the Free Software Foundation, either version 3 of the License, or
##                          any later version.
##
##                          This program is distributed in the hope that it will be useful,
##                          but WITHOUT ANY WARRANTY; without even the implied warranty of
##                          MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
##                          GNU General Public License for more details. See <http://www.gnu.org/licenses/>
##
##          Change Log:     05-01-2015 DPA      Created.
##                          08-08-2015 DPA      Added TOR, OpenBL, split out Palevo into its own function.
##                          09-06-2015 DPA	Cross-platform enhancements.
##			    09-17-2015 DPA	Added domains and URLs to the mix.
##                          03-19-2016 DPA      Added threat lists from AutoShun and CI Badguys
##                          12-04-2016 DPA	More robust handling of AlienVault.
##                          02-03-2017 DPA	3 new Ransomware lists. Disabled AutoShun.
##
##########################################################################################################################


from time import gmtime, strftime

import urllib2
import re

#Original script concept from a bash script that was a posting on: www.deepimpact.io/blog/splunkandfreeopen-sourcethreatintelligencefeeds


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

#Threat List URL's go here. Note that each list requires special parsing rules contained below.
urlList = ['http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt',
           'http://rules.emergingthreats.net/blockrules/compromised-ips.txt',
           'http://www.binarydefense.com/banlist.txt',
           'https://sslbl.abuse.ch/blacklist/sslipblacklist.csv',
           'https://reputation.alienvault.com/reputation.generic',
           'https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist',
           'https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist',
           'http://malc0de.com/bl/IP_Blacklist.txt',
           'https://check.torproject.org/exit-addresses',
           'http://www.openbl.org/lists/base_1days.txt',
           'http://avant.it-mate.co.uk/dl/Tools/hpHosts/hosts.txt',
           'http://hosts-file.net/hphosts-partial.txt',
           'https://isc.sans.edu/feeds/suspiciousdomains_High.txt',
           'http://www.malwaredomainlist.com/hostslist/hosts.txt',
           'https://openphish.com/feed.txt',
           'http://data.phishtank.com/data/online-valid.csv',
	   'http://osint.bambenekconsulting.com/feeds/c2-ipmasterlist.txt',
           'http://www.talosintel.com/feeds/ip-filter.blf',
	   'http://malc0de.com/bl/ZONES',
	   'http://autoshun.org/files/shunlist.csv',
	   'http://cinsscore.com/list/ci-badguys.txt',
           'https://ransomwaretracker.abuse.ch/downloads/RW_IPBL.txt',
           'https://ransomwaretracker.abuse.ch/downloads/RW_DOMBL.txt',
           'https://ransomwaretracker.abuse.ch/downloads/RW_URLBL.txt']


script_version = "3.25"
user_agent_string = "Optiv Threat Intel v" + script_version

logfile_name_log =  "optiv_threat_lists_script" + strftime("%m-%d-%Y-%H-%M-%S", gmtime()) + ".log"
logfile_name_txt = "optiv_threat_lists" + strftime("%m-%d-%Y-%H-%M-%S", gmtime()) + ".log"
phishtank_logfile_name_log =  "optiv_phishtank" + strftime("%m-%d-%Y-%H-%M-%S", gmtime()) + ".log"
hphosts_logfile_name_log =  "optiv_hphosts" + strftime("%m-%d-%Y-%H-%M-%S", gmtime()) + ".log"
binarydefense_logfile_name_log =  "optiv_binarydefense" + strftime("%m-%d-%Y-%H-%M-%S", gmtime()) + ".log"
alienvault_logfile_name_log =  "optiv_alienvault" + strftime("%m-%d-%Y-%H-%M-%S", gmtime()) + ".log"
logfile_name_txt = "optiv_threat_lists" + strftime("%m-%d-%Y-%H-%M-%S", gmtime()) + ".log"
bambenek_logfile_name_log =  "optiv_bambenek" + strftime("%m-%d-%Y-%H-%M-%S", gmtime()) + ".log"
talos_logfile_name_log = "optiv_talos_intel" + strftime("%m-%d-%Y-%H-%M-%S", gmtime()) + ".log"
ransomware_tracker_abuse_ch_log = "optiv_ransomware_tracker" + strftime("%m-%d-%Y-%H-%M-%S", gmtime()) + ".log"

'''
logfile_name =  os.path.join(splunk_home, 'etc', 'apps', 'optiv_threat_intel', 'bin', logfile_name_log)
outputfile_name =  os.path.join(splunk_home, 'etc', 'apps', 'optiv_threat_intel', 'bin', logfile_name_txt)
'''
logfile_name =  os.path.join(splunk_home, 'var', 'log', 'splunk', logfile_name_log)
phishtank_logfile_name =  os.path.join(splunk_home, 'var', 'log', 'splunk', phishtank_logfile_name_log)
bambenek_logfile_name = os.path.join(splunk_home, 'var', 'log', 'splunk', bambenek_logfile_name_log)
hphosts_logfile_name =  os.path.join(splunk_home, 'var', 'log', 'splunk', hphosts_logfile_name_log)
binarydefense_logfile_name =  os.path.join(splunk_home, 'var', 'log', 'splunk', binarydefense_logfile_name_log)
alienvault_logfile_name =  os.path.join(splunk_home, 'var', 'log', 'splunk', alienvault_logfile_name_log)
talos_logfile_name = os.path.join(splunk_home, 'var', 'log', 'splunk', talos_logfile_name_log)
ransomware_tracker_logfile_name = os.path.join(splunk_home, 'var', 'log', 'splunk', ransomware_tracker_abuse_ch_log)
outputfile_name =  os.path.join(splunk_home, 'var', 'log', 'splunk', logfile_name_txt)



print "logfile_name: " + logfile_name

lf = open(logfile_name,'w')
of = open(outputfile_name,'w')
phishtank_lf = open(phishtank_logfile_name,'w')
bambenek_lf = open(bambenek_logfile_name,'w')
hphosts_lf = open(hphosts_logfile_name,'w')
binarydefense_lf = open(binarydefense_logfile_name,'w')
alienvault_lf = open(alienvault_logfile_name,'w')
talos_lf = open(talos_logfile_name,'w')
ransomware_lf = open(ransomware_tracker_logfile_name,'w')

def getUrl(url,use_user_agent_bool):

    #url = urlList[0].strip('\n')
    print "URL: " + url

    if (use_user_agent_bool == 'true'):
        req = urllib2.Request(url, "",headers={'User-Agent' : user_agent_string})
    else:
        req = urllib2.Request(url)


    #Testing the URL here, print out error messages found.
    try: urllib2.urlopen(req)
    except urllib2.URLError, e:
        print e.reason
        lf.write( str(e.reason) + "\n")
    try:
        usock = urllib2.urlopen(req)

    except urllib2.HTTPError, err:
        if err.code == 404:
            print "Page not found!"
            lf.write( "Page not found!" )
            return 404

        elif err.code == 403:
            print "Access denied!"
            lf.write( "Access denied!" )
            return 403

        else:
            print "Something happened! Error code", err.code
            lf.write( "Something happened!")
            return -1

    except urllib2.URLError, err:
        print "Some other error happened:", err.reason
        lf.write("Some other error happened")
        return -1

    #usock = urllib2.urlopen(req)

    #************************************
    urlResults=usock.read()
    return urlResults

def parseTalosIntel(urlResults):
    talosIP = ['']

    talosIP_formatted = ['']

    talosIP = urlResults.split("\n")

    for line in talosIP:
        if (len(line) > 5):
            talosIP_formatted.append("dest_ip=" + line + " threat_list_name=talos_intel_IPs")

    print "Finished retrieving " + str(len(talosIP_formatted)) + " Talos Intel IPs."
    lf.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    talos_lf.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    talos_lf.write( "\n".join(talosIP_formatted))
    lf.write('\nRetrieved ' + str(len(talosIP_formatted)) + ' Talos Intel IPs.')

def parseRansomwareAbuseCHIPlist(urlResults):
    ransomwareAbuseIPNoHeaders = ['']
    ransomwareAbuseIP = ['']
    ransomwareAbuseIP_formatted = ['']

    ransomwareAbuseIPResults = urlResults.split("#########################################################")

    ransomwareAbuseIPNoHeaders = ransomwareAbuseIPResults[2:]

    for line in ransomwareAbuseIPNoHeaders:    
	parseRansomwareLine = line.split('\n')
        
	for line in parseRansomwareLine:
	    #print "line: " + str(line)
            if (len(line) > 2):
               ransomwareAbuseIP_formatted.append("dest_ip=" + str(line) + " threat_list_name=ransomware_Abuse_CH_IPs" )

    print "Finished retrieving " + str(len(ransomwareAbuseIP_formatted)) + " Ransomware Abuse CH IPs."
    lf.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    ransomware_lf.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    ransomware_lf.write( "\n".join(ransomwareAbuseIP_formatted))
    lf.write('\nRetrieved ' + str(len(ransomwareAbuseIP_formatted)) + ' Ransomware Abuse CH IPs.')

def parseRansomwareAbuseCHDomainlist(urlResults):
    ransomwareAbuseDomainNoHeaders = ['']
    ransomwareAbuseDomain = ['']
    ransomwareAbuseDomain_formatted = ['']

    ransomwareAbuseDomainResults = urlResults.split("#########################################################")

    ransomwareAbuseDomainNoHeaders = ransomwareAbuseDomainResults[2:]

    for line in ransomwareAbuseDomainNoHeaders:
        parseRansomwareLine = line.split('\n')

        for line in parseRansomwareLine:
            #print "line: " + str(line)
            if (len(line) > 2):
               ransomwareAbuseDomain_formatted.append("dest=" + str(line) + " threat_list_name=ransomware_Abuse_CH_domains" )

    print "Finished retrieving " + str(len(ransomwareAbuseDomain_formatted)) + " Ransomware Abuse CH Domains."
    lf.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    ransomware_lf.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    ransomware_lf.write( "\n".join(ransomwareAbuseDomain_formatted))
    lf.write('\nRetrieved ' + str(len(ransomwareAbuseDomain_formatted)) + ' Ransomware Abuse CH Domains.')

def parseRansomwareAbuseCHURLlist(urlResults):
    ransomwareAbuseURLNoHeaders = ['']
    ransomwareAbuseURL = ['']
    ransomwareAbuseURL_formatted = ['']

    ransomwareAbuseURLResults = urlResults.split("#########################################################")

    ransomwareAbuseURLNoHeaders = ransomwareAbuseURLResults[2:]

    for line in ransomwareAbuseURLNoHeaders:
        parseRansomwareLine = line.split('\n')

        for line in parseRansomwareLine:
            #print "line: " + str(line)
            if (len(line) > 2):
               ransomwareAbuseURL_formatted.append("url=" + str(line) + " threat_list_name=ransomware_Abuse_CH_URLs" )

    print "Finished retrieving " + str(len(ransomwareAbuseURL_formatted)) + " Ransomware Abuse CH URLs."
    lf.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    ransomware_lf.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    ransomware_lf.write( "\n".join(ransomwareAbuseURL_formatted))
    lf.write('\nRetrieved ' + str(len(ransomwareAbuseURL_formatted)) + ' Ransomware Abuse CH URLs.')



def parseBambenekconsultingIPList(urlResults):
    ##############################################################
    bambenekIP = ['']
    bambenekIP_formatted = ['']

    bambenekRowSplit = ['']

    bambenekResults = ['']

    bambenekNoHeaders = ['']

    bambenekResults = urlResults.split("#############################################################")

    bambenekNoHeaders = bambenekResults[2:]
    #print bambenekNoHeaders

    for line in bambenekNoHeaders:
        parseBambenekLine = line.split('\n')
        for cell in parseBambenekLine:
	    parseBambenekCell = cell.split(',')
	    if (len(parseBambenekCell) > 2):
                #print parseBambenekCell
                bambenekIP_formatted.append("dest_ip=" + parseBambenekCell[0] + " threat_list_name=bambenekIPs threat_description=\"" + parseBambenekCell[1] + "\" url=" + parseBambenekCell[3])
    print "Finished retrieving " + str(len(bambenekIP_formatted)) + " Bambenek IPs."
    lf.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    bambenek_lf.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    bambenek_lf.write( "\n".join(bambenekIP_formatted))
    lf.write('\nRetrieved ' + str(len(bambenekIP_formatted)) + ' Bambenek IPs.')

def parsePhishTankURLList(urlResults):
    phishTankURL = ['']
    phishTankURL_formatted = ['']
    phishTankRowSplit = ['']

    phishTankURL = urlResults.split('\n')

    for csvrow in phishTankURL[1:-1]:
        phishTankRowSplit = ['']
        phishTankRowSplit = csvrow.split(',')
        #print 'phishTankRowSplit: ' + str(phishTankRowSplit)
        if (len(phishTankRowSplit) > 7):
            #print 'phish tank len: ' +str(len(phishTankRowSplit))
            if (phishTankRowSplit[4] != 'yes'):
                phishTankRowSplit[4] = 'unknown'
            if (phishTankRowSplit[6] != 'yes'):
                phishTankRowSplit[6] = 'unknown'
            if (len(phishTankRowSplit[2]) < 12):
                phishTankRowSplit[2] = 'unknown'
            phishTankURL_formatted.append('url=' + phishTankRowSplit[1] + ' threat_list_name=Phish_Tank_URLs verified=' + phishTankRowSplit[4] + ' spoofed_org=' + phishTankRowSplit[7] + ' phishing_site_online=' + phishTankRowSplit[6] + ' phish_tank_info_url=' + phishTankRowSplit[2])


    print "Finished retrieving " +str(len(phishTankURL_formatted))+ " Phish Tank URLs."

    lf.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    phishtank_lf.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    phishtank_lf.write( "\n".join(phishTankURL_formatted))
    lf.write('\nRetrieved ' + str(len(phishTankURL_formatted)) + ' Phish Tank URLs.')

def parseOpenPhishURLList(urlResults):
    openPhishURL = ['']
    openPhishURL_formatted = ['']

    openPhishURL = urlResults.split('\n')


    for url in openPhishURL[:-1]:
        openPhishURL_formatted.append('url=' + url.strip() + ' threat_list_name=Open_Phish_URLs')
    #m = re.findall('^#Site^(.*?)^',urlResults,re.DOTALL|re.MULTILINE)
    #m = re.findall('^(.*\..*|.*\..*\..*|.*\..*\..*\..*|.*\..*\..*\..*\..*?)',urlResults,re.DOTALL|re.MULTILINE)
    #m = re.findall('^(((([A-Za-z0-9]+){1,63}\.)|(([A-Za-z0-9]+(\-)+[A-Za-z0-9]+){1,63}\.))+)$',urlResults,re.DOTALL|re.MULTILINE)
    #m = re.findall('^(((.*\..*)|(.*\..*\..*)|(.*\..*\..*\..*)))$',urlResults,re.DOTALL|re.MULTILINE)
    #m = re.findall('(.*\..*)',urlResults,re.DOTALL|re.MULTILINE)

    print "Finished retrieving " +str(len(openPhishURL_formatted))+ " Open Phish URLs."

    lf.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    of.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    of.write( "\n".join(openPhishURL_formatted))
    lf.write('\nRetrieved ' + str(len(openPhishURL_formatted)) + ' Open Phish URLs.')


def parseMalwareDomainList(urlResults):

    malwareDomain = ['']

    n = re.findall('127\.0\.0\.1(.*?)^127\.0\.0\.1',urlResults,re.DOTALL|re.MULTILINE)

    malwareDomain_formatted = ['']

    x=0

    #print "size n: " + str(len(n))


    for y in n:
        #print "in for loop"
        #print "y before loop: " + y
        if len(y) > 1:
            malwareDomain.append(('dest=' + n[x].strip().strip('\n') + ' threat_list_name=Malware_Domains').strip('\n') )
            #print 'dest=' + n[x]
        x=x+1
    #print "size n: " + str(len(n))
    #print torExitNodeIPs
    print "Finished retrieving " +str(len(malwareDomain))+ " Malware Domains."

    lf.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    of.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    of.write( "\n".join(malwareDomain))
    lf.write('\nRetrieved ' + str(len(malwareDomain)) + ' Malware Domains.')

def parseISCSANSSuspiciousDomainsList(urlResults):

    ISCSANSSuspiciousDomain = ['']
    ISCSANSSuspiciousDomain_formatted = ['']
    #print "ISCSANS: " + urlResults

    ISCSANSSuspiciousDomain = urlResults.split('Site\n')
    if len(ISCSANSSuspiciousDomain)>0:
		ISCSANSSuspiciousDomain = ISCSANSSuspiciousDomain[1].split('\n')

		for domain in ISCSANSSuspiciousDomain[:-11]:
			ISCSANSSuspiciousDomain_formatted.append('dest=' + domain.strip() + ' threat_list_name=ISC_SANS_Suspicious')
    #m = re.findall('^#Site^(.*?)^',urlResults,re.DOTALL|re.MULTILINE)
    #m = re.findall('^(.*\..*|.*\..*\..*|.*\..*\..*\..*|.*\..*\..*\..*\..*?)',urlResults,re.DOTALL|re.MULTILINE)
    #m = re.findall('^(((([A-Za-z0-9]+){1,63}\.)|(([A-Za-z0-9]+(\-)+[A-Za-z0-9]+){1,63}\.))+)$',urlResults,re.DOTALL|re.MULTILINE)
    #m = re.findall('^(((.*\..*)|(.*\..*\..*)|(.*\..*\..*\..*)))$',urlResults,re.DOTALL|re.MULTILINE)
    #m = re.findall('(.*\..*)',urlResults,re.DOTALL|re.MULTILINE)

    print "Finished retrieving " +str(len(ISCSANSSuspiciousDomain_formatted))+ " ISC SANS Suspicious Domains."

    lf.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    of.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    of.write( "\n".join(ISCSANSSuspiciousDomain_formatted))
    lf.write('\nRetrieved ' + str(len(ISCSANSSuspiciousDomain_formatted)) + ' ISC SANS Suspicious Domains.')



def parseHPHostsByMalwarebytesDomainList(urlResults):

    HPHostsByMalwarebytesDomain = ['']


    #HPHostsByMalwarebytesDomain = urlResults.split('!!!!^#')

    #HPHostsByMalwarebytesDomain = HPHostsByMalwarebytesDomain[1].split('\n')

    n = re.findall('127\.0\.0\.1(.*?)^127\.0\.0\.1',urlResults,re.DOTALL|re.MULTILINE)


    HPHostsByMalwarebytesDomain_formatted = ['']

    x=0

    for y in n:
        #print "in for loop"
        #print "y before loop: " + y
        if len(y) > 1:
            #print 'y before split: ' + y
            #y = y.split('   ')
            #print 'y after split: ' +y
            #HPHostsByMalwarebytesDomain_formatted.append(('domain=' + n[x] + ' threat_list_name=HPHostsByMalwareBytesDomains').strip('\n') )
            HPHostsByMalwarebytesDomain.append(('dest=' + n[x].strip().strip('\n') + ' threat_list_name=HP_Hosts_By_MalwareBytes').strip('\n') )
            #print 'dest=' + n[x]
        x=x+1

    print "Finished retrieving " +str(len(HPHostsByMalwarebytesDomain))+ " HP Hosts by MalwareBytes Domains."

    lf.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    hphosts_lf.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    hphosts_lf.write( "\n".join(HPHostsByMalwarebytesDomain))
    lf.write('\nRetrieved ' + str(len(HPHostsByMalwarebytesDomain)) + ' HP Hosts by MalwareBytes Domains')

def parseMalc0deDomains(urlResults):
    malcodeDomains = ['']
    line_split = ""

    malcodeDomains_formatted = ['']

    malcodeDomains = urlResults.split("\n")

    for line in malcodeDomains:
        if (len(line) > 5):
	    line_split = line.split('\"')
	    if (len(line_split) > 1):
		#print "line_split1: " + line_split[1]
		malcodeDomains_formatted.append("dest=" + line_split[1] + " threat_list_name=malc0de_Domains")

    print "Finished retrieving " + str(len(malcodeDomains_formatted)) + " Malc0de Domains."
    lf.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    of.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    of.write( "\n".join(malcodeDomains_formatted))
    lf.write('\nRetrieved ' + str(len(malcodeDomains_formatted)) + ' Malc0de Domains.')




def parseTorBlockList(urlResults):

    torExitNodeIPs = ['']

    m = re.findall('^ExitNode (.*?)^Published',urlResults,re.DOTALL|re.MULTILINE)
    n = re.findall('^LastStatus (.*?)^ExitAddress',urlResults,re.DOTALL|re.MULTILINE)
    o = re.findall('^ExitAddress (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) ',urlResults,re.DOTALL|re.MULTILINE)

    x=0


    for y in m:
        if len(y) > 1:
            torExitNodeIPs.append(('dest_ip=' + o[x] + ' threat_list_name=TorExitNodes last_status_date=\'' + n[x].strip('\n') + '\' ' + 'exit_node_id=' + m[x] ).strip('\n') )
        x=x+1

    #print torExitNodeIPs
    print "Finished retrieving " +str(len(torExitNodeIPs))+ " TorExitNodes."

    lf.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    of.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    of.write( "\n".join(torExitNodeIPs))
    lf.write('\nRetrieved ' + str(len(torExitNodeIPs)) + ' IPs from TorExitNodes')


def parseOpenBL(urlResults):


    openBLIPs = urlResults.split('# source ip')

    openBLIPs = openBLIPs[1].split('\n')

    openBLIPs_formatted = ['']


    for ip in openBLIPs:
        openBLIPs_formatted.append('dest_ip=' + ip + ' threat_list_name=OpenBL_1day')


    print "Finished retrieving " + str(len(openBLIPs)) + " IPs from Open Blocklist base 1 day."
    #of.write(zeusIPs_formatted)
    lf.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    of.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    of.write( "\n".join(openBLIPs_formatted))
    lf.write('\nRetrieved ' + str(len(openBLIPs)) + ' IPs from Open Blocklist base 1 day.')

def parseZeus(urlResults):


    zeusIPs = urlResults.split('##############################################################################')

    zeusIPs = zeusIPs[2].split('\n')

    zeusIPs_formatted = ['']


    for ip in zeusIPs:
        zeusIPs_formatted.append('dest_ip=' + ip + ' threat_list_name=Zeus')


    print "Finished retrieving " + str(len(zeusIPs)) + " IPs from Zeus."
    #of.write(zeusIPs_formatted)
    lf.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    of.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    of.write( "\n".join(zeusIPs_formatted))
    lf.write('\nRetrieved ' + str(len(zeusIPs)) + ' IPs from Zeus')

def parsePalevo(urlResults):


    palevoIPs = urlResults.split('# Palevo C&C IP Blocklist by abuse.ch')

    palevoIPs = palevoIPs[1].split('\n')

    palevoIPs_formatted = ['']


    for ip in palevoIPs:
        palevoIPs_formatted.append('dest_ip=' + ip + ' threat_list_name=Palevo_CandC')


    print "Finished retrieving " + str(len(palevoIPs)) + " IPs from Palevo."

    #of.write(zeusIPs_formatted)
    lf.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    of.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    of.write( "\n".join(palevoIPs_formatted))
    lf.write('\nRetrieved ' + str(len(palevoIPs)) + ' IPs from Palevo')

def parseEmergingThreatsBlockList(urlResults):
    m = re.findall('^#Spamhaus DROP Nets(.*?)^#Dshield Top Attackers',urlResults,re.DOTALL|re.MULTILINE)

    spamHausIPs = m[0].split()
    #print spamHausIPs
    spamHausIPs_formatted = ['']

    for ip in spamHausIPs:
        if len(ip) > 1:
            spamHausIPs_formatted.append('dest_ip=' + ip + ' threat_list_name=Spamhaus_Drop_Nets')


    #print spamHausIPs_formatted
    print "Finished retrieving " + str(len(spamHausIPs)) + " IPs from SpamHaus."

    lf.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    of.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    of.write( "\n".join(spamHausIPs_formatted))
    lf.write('\nRetrieved ' + str(len(spamHausIPs)) + ' IPs from SpamHaus')

    ###############################
    '''
    n = re.findall('^# Palevo(.*?)^#Spamhaus DROP Nets',urlResults,re.DOTALL|re.MULTILINE)

    palevoIPs = n[0].split()

    palevoIPs_formatted = ['']

    for ip in palevoIPs:
        if len(ip) > 1:
            palevoIPs_formatted.append('dest_ip=' + ip + ' threat_list_name=Palevo')


    print "Finished retrieving " + str(len(palevoIPs)) + " IPs from Palevo."
    #of.write(palevoIPs_formatted)

    lf.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    of.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    of.write( "\n".join(palevoIPs_formatted))

    lf.write('\nRetrieved ' + str(len(palevoIPs)) + ' IPs from Palevo')
    '''

    ###############################

    dshieldIPs = urlResults.split('#Dshield Top Attackers')

    dshieldIPs = dshieldIPs[1].split('\n')

    dshieldIPs_formatted = ['']

    for ip in dshieldIPs:
        if len(ip) > 1:
            dshieldIPs_formatted.append('dest_ip=' + ip + ' threat_list_name=Dshield_Top_Attackers')


    print "Finished retrieving " + str(len(dshieldIPs)) + " IPs from Dshield."
    #of.write(dshieldIPs_formatted)
    lf.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    of.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    of.write( "\n".join(dshieldIPs_formatted))
    lf.write('\nRetrieved ' + str(len(dshieldIPs)) + ' IPs from Dshield')
    ###############################

    '''
    o = re.findall('^# Zeus(.*?)^# Spyeye',urlResults,re.DOTALL|re.MULTILINE)

    zeusIPs = o[0].split()
    #print spamHausIPs
    zeusIPs_formatted = ['']

    for ip in zeusIPs:
        zeusIPs_formatted.append('dest_ip=' + ip + ' threat_list_name=Zeus')


    print "Finished retrieving " + str(len(zeusIPs)) + " IPs from Zeus."
    #of.write(zeusIPs_formatted)
    lf.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    of.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    of.write( "\n".join(zeusIPs_formatted))
    lf.write('\nRetrieved ' + str(len(zeusIPs)) + ' IPs from Zeus')
    '''

    ###############################
    p = re.findall('^# Feodo(.*?)^# Zeus',urlResults,re.DOTALL|re.MULTILINE)
    #spamHausIPs = m[0].strip('\n')
    #spamHausIPs = m[0]


    feodoIPs = p[0].split()
    #print spamHausIPs
    feodoIPs_formatted = ['']

    for ip in feodoIPs:
        if len(ip) > 1:
            feodoIPs_formatted.append('dest_ip=' + ip + ' threat_list_name=Feodo')


    print "Finished retrieving "+ str(len(feodoIPs))  + " IPs from Feodo."
    #of.write(feodoIPs_formatted)
    lf.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    of.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    of.write( "\n".join(feodoIPs_formatted))
    lf.write('\nRetrieved ' + str(len(feodoIPs)) + ' IPs from Feodo')
    ########################

def parseEmergingThreatsCompromisedIPs(urlResults):
    compromisedIPs = urlResults.split()
    compromisedIPs_formatted = ['']

    for ip in compromisedIPs:
        if len(ip) > 1:
            compromisedIPs_formatted.append('dest_ip=' + ip + ' threat_list_name=Emerging_Threats_Compromised_IPs')


    print "Finished retrieving "+ str(len(compromisedIPs))  +" Emerging Threats Compromised IPs."
    #of.write(compromisedIPs_formatted)
    lf.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    of.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    of.write( "\n".join(compromisedIPs_formatted))
    lf.write('\nRetrieved ' + str(len(compromisedIPs)) + ' IPs from Emerging Threats Compromised IPs')

    #************************************

def parseBinaryDefenseIPs(urlResults):
    ###############################

    binaryDefenseIPs = urlResults.split('#\n#\n#\n')

    #print binaryDefenseIPs

    binaryDefenseIPs = binaryDefenseIPs[2].split('\n')
    #binaryDefenseIPs = binaryDefenseIPs[1].split('\n')

    binaryDefenseIPs_formatted = ['']

    for ip in  binaryDefenseIPs:
        if len(ip) > 1:
            binaryDefenseIPs_formatted.append('dest_ip=' + ip + ' threat_list_name=Binary_Defense_IPs')


    print "Finished retrieving "+ str(len(binaryDefenseIPs)) +" IPs from Binary Defense."

    lf.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    binarydefense_lf.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    binarydefense_lf.write( "\n".join(binaryDefenseIPs_formatted))
    lf.write('\nRetrieved ' + str(len(binaryDefenseIPs)) + ' IPs from Binary Defense')

    #************************************

def parseAbuseCHSSLIPBLIPs(urlResults):
    Abuse_CH_SSL_IPBLIPs = urlResults.split('# DstIP,DstPort')

    Abuse_CH_SSL_IPBLIPs =  Abuse_CH_SSL_IPBLIPs[1].split('\n')

    #Abuse_CH_SSL_IPBLIPs.pop()
    Abuse_CH_SSL_IPBLIPs = Abuse_CH_SSL_IPBLIPs[1:]

    #print "abuses: " + str(Abuse_CH_SSL_IPBLIPs)

    Abuse_CH_SSL_IPBLIPs_formatted = ['']

    for ip in  Abuse_CH_SSL_IPBLIPs:
        #print "ip: " + ip

        if len(ip) > 1:
            if (len((str(ip)).split(',')) ==3 ):
                ip_addr,ssl_port,threat_desc = (str(ip)).split(',')

                threat_desc_no_spaces =re.sub(r' ', '_', threat_desc)
                #new_string = re.sub(r'"(\d+),(\d+)"', r'\1.\2', original_string)
                #lines.append((ip_addr,ssl_port,threat_type))

                Abuse_CH_SSL_IPBLIPs_formatted.append('dest_ip=' + ip_addr + ' dest_port=' + ssl_port + ' threat_description=' + threat_desc_no_spaces + ' threat_list_name=Abuse_CH_SSL_IP_Blocklist')
                 #binaryDefenseIPs_formatted.append('dest_ip=' + ip + ' threat_list_name=Abuse_CH_SSL_IPBL_IPs')


    #print "Finished retrieving Abuse_CH_SSL_IPBL."
    of.write(Abuse_CH_SSL_IPBLIPs_formatted)
    lf.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    of.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    of.write( "\n".join(Abuse_CH_SSL_IPBLIPs_formatted))
    lf.write('\nRetrieved ' + str(len(Abuse_CH_SSL_IPBLIPs)) + ' IPs from Abuse_CH_SSL_IPBL')


    #************************************

def parseMalc0deIPs(urlResults):
    malc0deIPs = urlResults.split('\n\n')

    malc0deIPs =  malc0deIPs[1].split('\n')

    malc0deIPs_formatted = ['']

    for ip in  malc0deIPs:
        if len(ip) > 1:
            malc0deIPs_formatted.append('dest_ip=' + ip + ' threat_list_name=malc0de_IPs')


    print "Finished retrieving "+ str(len(malc0deIPs)) +" malc0de_IPs."

    lf.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    of.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    of.write( "\n".join(malc0deIPs_formatted))
    lf.write('\nRetrieved ' + str(len(malc0deIPs)) + ' IPs from malc0de_IPs')

    #************************************

def parseAlienVault(urlResults):
    #urlResults=usock.read()
    ###############################

    AlienVaultIPs = urlResults.split('# Generic format')

    AlienVaultIPs =  AlienVaultIPs[1].split('\n')

    AlienVaultIPs_formatted = ['']

    for ip in  AlienVaultIPs:
        if len(ip) > 1:

            ip_addr,metadata =(str(ip)).split('#')

            threat_desc,region,latitude,longitude=(str(metadata)).split(',')

            threat_desc_no_spaces =re.sub(r' ', '_', threat_desc)
            threat_desc_no_spaces =re.sub(r';', '_and_', threat_desc_no_spaces)
            region_no_spaces =re.sub(r' ', '_', region)


            AlienVaultIPs_formatted.append('dest_ip=' + ip_addr + ' threat_description=' + threat_desc_no_spaces + ' region='+ region_no_spaces + ' latitude=' + latitude + ' longitude='+longitude+' threat_list_name=AlienVault_IP_Blocklist')


    print "Finished retrieving "+ str(len(AlienVaultIPs)) +" IPs from AlienVault."
    #of.write(AlienVaultIPs_formatted)

    lf.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT\n')
    alienvault_lf.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT\n')
    alienvault_lf.write( "\n".join(AlienVaultIPs_formatted))
    lf.write('\nRetrieved ' + str(len(AlienVaultIPs)) + ' IPs from AlienVaultIPs')

def parseAutoshunIPs(urlResults):
    autoshunIPs = urlResults.split('\n')

    #autoshunIPs =  autoshunIPs[1].split('\n')

    autoshunIPs_formatted = ['']

    threat_desc_no_spaces = ''

    for line in autoshunIPs:
        if len(line) > 5:
	    line_split = line.split(',')
	    if (len(line_split) > 2):
		#print "line_split0: " + line_split[0]
		#print "line_split2: " + line_split[2]
		threat_desc_no_spaces =re.sub(r' ', '_', line_split[2])
		autoshunIPs_formatted.append("dest_ip=" + line_split[0] + " threat_list_name=autoshun_IPs threat_description=" + threat_desc_no_spaces)


    print "Finished retrieving "+ str(len(autoshunIPs)) +" AutoShun IPs."

    lf.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    of.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    of.write( "\n".join(autoshunIPs_formatted))
    lf.write('\nRetrieved ' + str(len(autoshunIPs)) + ' IPs from AutoShun IPs')

def parseCI_Army_BadguysIPs(urlResults):
    CI_Army_Badguys_IPs = urlResults.split('\n')

    CI_Army_Badguys_IPs_formatted = ['']


    for line in CI_Army_Badguys_IPs:
        if len(line) > 5:
	    line_split = line.split('.')
	    #print "len_line_split:" + str(len(line_split))
	    if (len(line_split) > 3):
		#threat_desc_no_spaces =re.sub(r' ', '_', line_split[2])
		CI_Army_Badguys_IPs_formatted.append("dest_ip=" + line + " threat_list_name=CI_Army_Badguys_IPs")


    print "Finished retrieving "+ str(len(CI_Army_Badguys_IPs)) +" CI Army Badguys IPs."

    lf.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    of.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    of.write( "\n".join(CI_Army_Badguys_IPs_formatted))
    lf.write('\nRetrieved ' + str(len(CI_Army_Badguys_IPs)) + ' IPs from CI Army Badguys')

    #************************************

def main():


    lf.write('[*] Script Started at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT\n')
    of.write('[*] Script Started at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT\n')
    lf.write('[*] Script version: ' + script_version + '\n')
    print '[*] Script Started at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT\n'

    print '[*] Script version: ' + script_version
    raw_threatlist = ""

      #problem?
    #raw_threatlist = getUrl(urlList[3].strip('\n'))
    #print len(str(raw_threatlist))
    #if len(str(raw_threatlist)) > 3:
    #    parseAbuseCHSSLIPBLIPs(raw_threatlist)

    raw_threatlist = getUrl(urlList[0].strip('\n'),'true')
    if len(str(raw_threatlist)) > 3:
    	parseEmergingThreatsBlockList(raw_threatlist)

    raw_threatlist = getUrl(urlList[1].strip('\n'),'true')
    if len(str(raw_threatlist)) > 3:
        parseEmergingThreatsCompromisedIPs(raw_threatlist)

    raw_threatlist = getUrl(urlList[2].strip('\n'),'true')
    if len(str(raw_threatlist)) > 3:
        parseBinaryDefenseIPs(raw_threatlist)

    raw_threatlist = getUrl(urlList[7].strip('\n'),'true')
    if len(str(raw_threatlist)) > 3:
        parseMalc0deIPs(raw_threatlist)

    raw_threatlist = getUrl(urlList[4].strip('\n'),'false')
    if len(str(raw_threatlist)) > 3:
        parseAlienVault(raw_threatlist)

    raw_threatlist = getUrl(urlList[8].strip('\n'),'true')
    if len(str(raw_threatlist)) > 3:
        parseTorBlockList(raw_threatlist)

    raw_threatlist = getUrl(urlList[5].strip('\n'),'true')
    if len(str(raw_threatlist)) > 3:
        parseZeus(raw_threatlist)

    raw_threatlist = getUrl(urlList[6].strip('\n'),'true')
    if len(str(raw_threatlist)) > 3:
        parsePalevo(raw_threatlist)

    raw_threatlist = getUrl(urlList[9].strip('\n'),'true')
    if len(str(raw_threatlist)) > 3:
        parseOpenBL(raw_threatlist)

    raw_threatlist = getUrl(urlList[10].strip('\n'),'false')
    if len(str(raw_threatlist)) > 3:
        parseHPHostsByMalwarebytesDomainList(raw_threatlist)

    raw_threatlist = getUrl(urlList[13].strip('\n'),'false')
    if len(str(raw_threatlist)) > 3:
        parseMalwareDomainList(raw_threatlist)

    raw_threatlist = getUrl(urlList[12].strip('\n'),'true')
    if len(str(raw_threatlist)) > 3:
        parseISCSANSSuspiciousDomainsList(raw_threatlist)

    raw_threatlist = getUrl(urlList[14].strip('\n'),'false')
    if len(str(raw_threatlist)) > 3:
        parseOpenPhishURLList(raw_threatlist)

    raw_threatlist = getUrl(urlList[15].strip('\n'),'true')
    if len(str(raw_threatlist)) > 3:
        parsePhishTankURLList(raw_threatlist)

    #raw_threatlist = getUrl(urlList[0].strip('\n'),'true')
    raw_threatlist = getUrl(urlList[16].strip('\n'),'true')
    if len(str(raw_threatlist)) > 3:
	parseBambenekconsultingIPList(raw_threatlist)

    raw_threatlist = getUrl(urlList[17].strip('\n'),'true')

    if len(str(raw_threatlist)) > 3:
         parseTalosIntel(raw_threatlist)


    raw_threatlist = getUrl(urlList[18].strip('\n'),'true')

    if len(str(raw_threatlist)) > 3:
         parseMalc0deDomains(raw_threatlist)

    #raw_threatlist = getUrl(urlList[19].strip('\n'),'true')

    #if len(str(raw_threatlist)) > 3:
    #     parseAutoshunIPs(raw_threatlist)

    raw_threatlist = getUrl(urlList[20].strip('\n'),'true')

    if len(str(raw_threatlist)) > 3:
         parseCI_Army_BadguysIPs(raw_threatlist)

    raw_threatlist = getUrl(urlList[21].strip('\n'),'true')
    if len(str(raw_threatlist)) > 3:
         parseRansomwareAbuseCHIPlist(raw_threatlist)

    raw_threatlist = getUrl(urlList[22].strip('\n'),'true')
    if len(str(raw_threatlist)) > 3:
         parseRansomwareAbuseCHDomainlist(raw_threatlist)

    raw_threatlist = getUrl(urlList[23].strip('\n'),'true')
    if len(str(raw_threatlist)) > 3:
         parseRansomwareAbuseCHURLlist(raw_threatlist)


if __name__ == '__main__':
	main()



