#!/usr/bin/env python

# Analyze the projects listed in a CSV file, e.g., "projects_to_examine.csv",
# producing "results.csv" that contains a collection of metrics.
# (C) 2015 Institute for Defense Analyses (IDA)
# Authors: Samir Khakimov and David A. Wheeler

# This code is written assuming that speed is irrelevant.
# If speed matters, it should be easy to modify.
# It does use caches to reduce the number external acquisitions.

# This software is released as open source software under the "MIT" license:
#
# Permission is hereby granted, free of charge, to any person obtaining a
# copy of this software and associated documentation files (the "Software"),
# to deal in the Software without restriction, including without limitation
# the rights to use, copy, modify, merge, publish, distribute, sublicense,
# and/or sell copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included
# in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
# THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
# OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
# ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
# OTHER DEALINGS IN THE SOFTWARE.

# Enable Python 3 capabilities/syntax in Python 2.
from __future__ import print_function#, unicode_literals
from __future__ import absolute_import, division
try:
   xrange = xrange
   # We have Python 2
except:
   xrange = range
   # We have Python 3
# From here on use "xrange", not "range".

import sys, urllib, re
import xml.etree.ElementTree as ET
import csv
import argparse
import os
from bs4 import BeautifulSoup
import json
from datetime import datetime
import calendar, time

debian_data = {}
debian_pop = {}
popualrity_threshold = 0
api_key = '' #openhub
# Values to extract from debian apt for each project:
debian_include = ['Source: ', 'Version: ', 'Description: ', 'Homepage: ']

#save web results locally for caching purposes
def cache_data(url, destination):
  folder = destination.split('/')[0] + '/'
  if not os.path.exists(folder):
    os.makedirs(folder)
  f = urllib.urlopen(url)
  contents = f.read()
  cache_file = open(destination, 'w')
  cache_file.write(contents)
  cache_file.close()

# Remove non-ascii chars from a list of strings
def remove_non_ascii(text_list):
  for value in text_list:
    if value is not None:
      new_value = ''.join([i if ord(i) < 128 else ' ' for i in value])
      text_list[text_list.index(value)] = new_value

  return text_list

def get_debian():
  package_data = ['']*len(debian_include)
  ret = {}
  for line in open('apt_cache_dumpavail.txt'):
    if line.startswith('Package: '):
      package_name = line[len('Package:'):].strip()
      continue
    for value in debian_include:
      if line.startswith(value):
        package_data[debian_include.index(value)] = line[len(value):].strip()
        continue
    # if line is blank, that means there is no more information for a package
    if not line.strip():
      ret[package_name] = package_data
      package_data = ['']*len(debian_include)

  return ret


def get_debian_pop():
  ret = {}
  for line in open('by_inst'):
    if not line.startswith('#') and not line.startswith('---'):
      data = line.split()
      # Keys are project names and values are popularities
      ret[data[1]] = int(data[2])

  return ret

class Oss_Package(object):

  def __init__(self,package_name,cve_keyword,openhub_key,direct_network_exposure, process_network_data, potential_privilege_escalation, comment_on_priority):
    self.package_name = package_name
    self.cve_keyword = cve_keyword#CVE search keyword for MITRE database
    self.openhub_key = openhub_key
    self.direct_network_exposure = direct_network_exposure
    self.process_network_data = process_network_data
    self.potential_privilege_escalation = potential_privilege_escalation
    self.comment_on_priority = comment_on_priority

    project_debian_data = debian_data[self.package_name]
    self.debian_source = project_debian_data[0]
    self.debian_version = project_debian_data[1]
    self.debian_desc = project_debian_data[2]
    self.debian_home = project_debian_data[3]

    self.popularity = str(debian_pop[self.package_name])
    
  #get project's details from https://www.openhub.net/
  def get_openhub(self):
    project_tags = ['name', 'description', 'homepage_url', 'download_url'] #from https://www.openhub.net/
    analysis_tags = ['twelve_month_contributor_count', 'total_contributor_count','total_code_lines', 'main_language_name'] # from https://www.openhub.net/
    factoid_types = ['FactoidActivity', 'FactoidAge', 'FactoidComments', 'FactoidTeamSize'] # from https://www.openhub.net/

    self.openhub_name = ''
    self.openhub_desc = ''
    self.openhub_home = ''
    self.openhub_download = ''
    self.twelve_month_contributor_count = ''
    self.total_contributor_count = ''
    self.total_code_lines = ''
    self.main_language = ''
    self.licenses = ''
    self.fact_activity = ''
    self.fact_age = ''
    self.fact_comments = ''
    self.fact_team_size = ''
    self.openhub_page = ''
    self.implemented = ''
    self.role = ''

    if self.openhub_key != '':
      self.openhub_page = 'https://www.openhub.net/projects/'+self.openhub_key
      
      # Results are saved. Store data if it's not in the cache
      filename = "openhub_cache/"+self.openhub_key + '.xml'
      if os.path.isfile(filename) == False:
        url = 'https://www.openhub.net/projects/'+self.openhub_key+'.xml?api_key='+api_key
        cache_data(url,filename)

      tree = ET.parse(filename)
      elem = tree.getroot()
      #project tags
      tag = elem.find("result/project/name")
      if tag is not None:
        self.openhub_name = tag.text

      tag = elem.find("result/project/description")
      if tag is not None:
        self.openhub_desc = tag.text

      tag = elem.find("result/project/homepage_url")
      if tag is not None and tag.text is not None:
        self.openhub_home = tag.text

      tag = elem.find("result/project/download_url")
      if tag is not None:
        self.openhub_download = tag.text
      #analysis tags
      tag = elem.find("result/project/analysis/twelve_month_contributor_count")
      if tag is not None:
        self.twelve_month_contributor_count = str(tag.text)

      tag = elem.find("result/project/analysis/total_contributor_count")
      if tag is not None:
        self.total_contributor_count = tag.text

      tag = elem.find("result/project/analysis/total_code_lines")
      if tag is not None:
        self.total_code_lines = tag.text

      tag = elem.find("result/project/analysis/main_language_name")
      if tag is not None:
        self.main_language = tag.text

      for licence in elem.findall("result/project/licenses/license/name"):
        if licence is not None:
          self.licenses+=licence.text+' '

      for factoid in elem.findall("result/project/analysis/factoids/factoid"):
        factoid_type = factoid.attrib.get('type')
        if 'FactoidActivity' in factoid_type:
          self.fact_activity = factoid.text.strip()
        elif 'FactoidAge' in factoid_type:
          self.fact_age = factoid.text.strip()
        elif 'FactoidComments' in factoid_type:
          self.fact_comments = factoid.text.strip()
        elif 'FactoidTeamSize' in factoid_type:
          self.fact_team_size = factoid.text.strip()


  # Get CVE info from https://cve.mitre.org (currently this function is not called)
  def get_cve_data_mitre(self):
    self.mitre_cve_since_2010 = ''
    self.mitre_cve_page = ''
    if self.cve_keyword != '':
      filename = "cve_cache/"+self.cve_keyword + '.html'
      url = 'https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword='+self.cve_keyword
      if os.path.isfile(filename) == False:
        cache_data(url, filename)

      soup = BeautifulSoup(open("cve_cache/"+self.cve_keyword + '.html'))
      # Find all href references containing CVE within a page (only looks for 2010 and after)
      cve_numbers = soup.find_all(href=re.compile('CVE-201'))
      self.mitre_cve_since_2010 = str(len(cve_numbers))
      self.mitre_cve_page = url

  def get_cve_debian(self):
    if self.debian_source != '':
      lookup = self.debian_source.split()[0] # use only the first word of a source for lookup
    else:
      lookup = self.package_name
    filename = 'debian_cve/'+lookup +'.html'
    url = 'https://security-tracker.debian.org/tracker/source-package/'+lookup 
    if os.path.isfile(filename) == False:
      cache_data(url, filename)

    soup = BeautifulSoup(open(filename))
    cve_numbers = soup.find_all(href=re.compile('CVE-201'))
    self.cve_since_2010 = str(len(cve_numbers))
    self.cve_page = url

  def get_role_debian(self): # Identify if a package is data or info
    filename = 'debian_role/' + self.package_name + '.html'
    url = 'https://packages.debian.org/wheezy/' + self.package_name
    if os.path.isfile(filename) == False:
      cache_data(url,filename)
    soup = BeautifulSoup(open(filename))
    tag = soup.find(href = re.compile('#implemented-in'))
    if tag is not None:
      self.implemented = tag.text
    tag = soup.find(href = re.compile('#role'))
    if tag is not None:
      self.role = tag.text    

  def get_risk_index(self):
    ret = 0
    # If no homepage, add one
    if len(self.debian_home)==0 and len(self.openhub_home)==0:
      ret += 1
    if self.main_language.upper() in ['C','C++'] or self.implemented in ['C','C++']: # if implemented in C/C++, add two
      ret += 2
    ret += {0:0,1:1,2:2,3:2}.get(self.cve_since_2010,3) # Add points depending on number of CVEs
    # Add points depending on number of recent contributors
    ret += {0:5,1:4,2:4,3:4,'':2}.get(self.twelve_month_contributor_count,0)
    if int(self.popularity) >= popularity_threshold: # if popular, add 1 point
      ret += 1
    if  'Data' in self.role: # If this is not a program, subtract three
      ret -= 3
    ret += 2*int(self.direct_network_exposure) + int(self.process_network_data) + int(self.potential_privilege_escalation) # network exposure is weighted more
    self.risk_index = str(ret)


def main():
  global api_key
  global debian_data
  global debian_pop
  global popularity_threshold

  parser = argparse.ArgumentParser(description = 'OSS Metrics', usage ='python program.py -p projects_to_examine.csv')
  parser.add_argument('-p','--project_file', help='path to csv file with project list', required = True)

  args = parser.parse_args()

  f = open('openhub_key.txt','r') # API key must be stored in a text file, same directory
  api_key = f.readline().strip()

  debian_data = get_debian() # dict instance with debian data(source, version, description,homepage)
  debian_pop = get_debian_pop() # dict instance with total installs per package
  project_name_list = []
  package_list = []

  project_file = open(args.project_file)
  project_reader = csv.reader(project_file, delimiter = ',')
  headers = project_reader.next()
  for project_info in project_reader:
    project_name = project_info[headers.index('Debian_Package')].strip()
    if project_name == '':
      continue
    project_name_list.append(project_name)

  debian_pop = {project_name: debian_pop.get(project_name, 0) for project_name in project_name_list}
  debian_data = {project_name: debian_data.get(project_name, ['']*len(debian_include)) for project_name in project_name_list}
  popularity_threshold = sorted(debian_pop.values())[int(0.1*len(debian_pop.values()))] # popularity of lowest 10%th percentile

  with open(args.project_file) as project_file:
    project_reader = csv.reader(project_file, delimiter = ',')
    headers = project_reader.next()
    for project_info in project_reader:
      project_name = project_info[headers.index('Debian_Package')].strip()
      if project_name == '':
        continue
      print(project_name)
      openhub_name = project_info[headers.index('openhub_name')].strip()
      cve_keyword = project_info[headers.index('cve_keyword')].strip()
      direct_network_exposure = project_info[headers.index('direct_network_exposure')]
      process_network_data = project_info[headers.index('process_network_data')]
      potential_privilege_escalation = project_info[headers.index('potential_privilege_escalation')]
      comment_on_priority = project_info[headers.index('comment_on_priority')]

      Package = Oss_Package(project_name, cve_keyword, openhub_name,direct_network_exposure,process_network_data,potential_privilege_escalation, comment_on_priority)
      Package.get_openhub()
      Package.get_cve_debian()
      Package.get_role_debian()
      Package.get_risk_index()
      package_list.append(Package)
 
  # Sort by risk index
  package_list.sort(key = lambda package: int(package.risk_index), reverse = True)

  # Add the headers row
  with open('results.csv','w') as csvfile:
    headerwriter = csv.writer(csvfile, delimiter = ',')
    headerwriter.writerow(['project_name','debian_source','debian_version','debian_desc','debian_home','CVE_since_2010','CVE_page','openhub_page',     'openhub_name','openhub_desc','openhub_home','openhub_download','twelve_month_contributor_count','total_contributor_count','total_code_lines','main_language_name',     'licenses','fact_activity', 'fact_age', 'fact_comments', 'fact_team_size', 'package_popularity','implemented_in','role','direct_network_exposure','process_network_data','potential_privilege_escalation', 'risk_index(max = 16)', 'comment_on_priority'])

  csvfile = open('results.csv','a')
  resultwriter = csv.writer(csvfile, delimiter = ',')
  # Write each package results into csv
  for p in package_list:
    row = [p.package_name, p.debian_source, p.debian_version, p.debian_desc, p.debian_home, p.cve_since_2010, p.cve_page,  p.openhub_page, p.openhub_name, p.openhub_desc, p.openhub_home, p.openhub_download, p.twelve_month_contributor_count, p.total_contributor_count, p.total_code_lines, p.main_language, p.licenses, p.fact_activity, p.fact_age, p.fact_comments, p.fact_team_size, p.popularity, p.implemented,p.role,p.direct_network_exposure, p.process_network_data, p.potential_privilege_escalation, p.risk_index, p.comment_on_priority]
    resultwriter.writerow(remove_non_ascii(row))
  
if __name__== "__main__":
  main()

