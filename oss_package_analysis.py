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
from __future__ import print_function
from __future__ import absolute_import, division
try:
   xrange = xrange
   # We have Python 2
except:
   xrange = range
   # We have Python 3
# From here on use "xrange", not "range".

import urllib
import re
import xml.etree.ElementTree as ET
import csv
import argparse
import os
import sys
from bs4 import BeautifulSoup

debian_data = {}
debian_pop = {}
popualrity_threshold = 0
openhub_api_key = ''
# Values to extract from debian apt-cache for each project
debian_include = ['Source:', 'Version:', 'Description:', 'Homepage:']


def cache_data(url, destination):
  '''Save web results locally for caching purposes'''
  folder = destination.split('/')[0] + '/'
  if not os.path.exists(folder):
    os.makedirs(folder)
  f = urllib.urlopen(url)
  contents = f.read()
  cache_file = open(destination, 'w')
  cache_file.write(contents)
  cache_file.close()


def remove_non_ascii(text_list):
  '''Remove non-ascii chars from a list of strings'''
  for value in text_list:
    if value is not None:
      new_value = ''.join([i if ord(i) < 128 else ' ' for i in value])
      text_list[text_list.index(value)] = new_value.strip()
  return text_list


def get_debian():
  '''
  Convert information from apt-cache dumpavail output to
  dictionary form with indicated fields
  '''
  try:
    file = open('apt_cache_dumpavail.txt', 'r')
  except IOError:
    print('Please include apt_cache_dumpavail.txt into the working directory.')
    sys.exit(1)

  package_data = {}
  all_packages = {}
  for line in open('apt_cache_dumpavail.txt'):
    if line.startswith('Package:'):
      package_name = line[len('Package:'):].strip()
      continue
    for value in debian_include:
      if line.startswith(value):
        package_data[value.strip(':')] = line[len(value):].strip()
        continue
    if 'implemented-in::' in line:
      first_index = line.index('implemented-in::')
      try:
        last_index = line.index(',', first_index)
      except ValueError:
        last_index = line.index('\n', first_index)
      package_data['implemented-in'] = line[first_index+len('implemented-in::'):last_index]
    if 'role::' in line:
      first_index = line.index('role::')
      try:
        last_index = line.index(',', first_index)
      except ValueError:
        last_index = line.index('\n', first_index)
      package_data['role'] = line[first_index+len('role::'):last_index]
    # If line is blank, that means there is no more information for a package
    if not line.strip():
      all_packages[package_name] = package_data
      package_data = {}

  return all_packages


def get_debian_pop():
  '''Obtain Debian popularity vote for each project'''
  try:
    file = open('by_inst', 'r')
  except IOError:
    print('Please include by_inst file with popularities into the working \
    directory. \nSee http://popcon.debian.org/by_inst')
    sys.exit(1)

  pop_dict = {}
  for line in open('by_inst'):
    if not line.startswith('#') and not line.startswith('---'):
      data = line.split()
      # Keys are project names and values are popularities
      pop_dict[data[1]] = int(data[2])
  return pop_dict


def get_pop_threshold(debian_pop):
  pop_values = sorted(debian_pop.values())
  tenth_percentile = int(0.1*len(pop_values))
  threshold = pop_values[tenth_percentile]
  return threshold


class Oss_Package(object):
  '''
  Class that represents an OSS package and corresponding attributes
  '''
  def __init__(self, package_name, openhub_lookup_name,
               direct_network_exposure, process_network_data,
               potential_privilege_escalation, comment_on_priority):
    self.package_name = package_name
    self.openhub_lookup_name = openhub_lookup_name
    self.direct_network_exposure = str(direct_network_exposure)
    self.process_network_data = str(process_network_data)
    self.potential_privilege_escalation = str(potential_privilege_escalation)
    self.comment_on_priority = comment_on_priority

    self.debian_source = debian_data[package_name].get('Source', '')
    self.debian_version = debian_data[package_name].get('Version', '')
    self.debian_desc = debian_data[package_name].get('Description', '')
    self.debian_home = debian_data[package_name].get('Homepage', '')
    self.implemented = debian_data[package_name].get('implemented-in', '')
    self.role = debian_data[package_name].get('role', '')

    self.popularity = str(debian_pop[package_name])

    self.website_points = 0
    self.CVE_points = 0
    self.recent_contributor_points = 0
    self.popularity_points = 0
    self.language_points = 0
    self.exposure_points = 0
    self.data_only_points = 0

  def get_openhub(self):
    '''Get project's details from https://www.openhub.net/'''
    project_tags = ['name', 'description', 'homepage_url', 'download_url']
    analysis_tags = ['twelve_month_contributor_count', 'total_contributor_count',
                     'total_code_lines', 'main_language_name']
    factoid_types = ['FactoidActivity', 'FactoidAge', 'FactoidComments',
                     'FactoidTeamSize']

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

    if self.openhub_lookup_name != '':
      self.openhub_page = 'https://www.openhub.net/projects/' + self.openhub_lookup_name

      # Results are saved. Store data if it's not in the cache
      filename = 'openhub_cache/'+self.openhub_lookup_name + '.xml'
      if os.path.isfile(filename) == False:
        url = 'https://www.openhub.net/projects/' + self.openhub_lookup_name +\
              '.xml?api_key=' + openhub_api_key
        cache_data(url, filename)

      tree = ET.parse(filename)
      elem = tree.getroot()
      # Project tags
      tag = elem.find('result/project/name')
      if tag is not None:
        self.openhub_name = tag.text

      tag = elem.find('result/project/description')
      if tag is not None:
        self.openhub_desc = tag.text

      tag = elem.find('result/project/homepage_url')
      if tag is not None and tag.text is not None:
        self.openhub_home = tag.text

      tag = elem.find('result/project/download_url')
      if tag is not None:
        self.openhub_download = tag.text
      # Analysis tags
      tag = elem.find('result/project/analysis/twelve_month_contributor_count')
      if tag is not None:
        self.twelve_month_contributor_count = str(tag.text).strip()

      tag = elem.find('result/project/analysis/total_contributor_count')
      if tag is not None:
        self.total_contributor_count = str(tag.text).strip()

      tag = elem.find('result/project/analysis/total_code_lines')
      if tag is not None:
        self.total_code_lines = str(tag.text).strip()

      tag = elem.find('result/project/analysis/main_language_name')
      if tag is not None:
        self.main_language = str(tag.text).strip()

      for licence in elem.findall('result/project/licenses/license/name'):
        if licence is not None:
          self.licenses += str(licence.text).strip()+' '

      for factoid in elem.findall('result/project/analysis/factoids/factoid'):
        factoid_type = factoid.attrib.get('type')
        if 'FactoidActivity' in factoid_type:
          self.fact_activity = factoid.text.strip()
        elif 'FactoidAge' in factoid_type:
          self.fact_age = factoid.text.strip()
        elif 'FactoidComments' in factoid_type:
          self.fact_comments = factoid.text.strip()
        elif 'FactoidTeamSize' in factoid_type:
          self.fact_team_size = factoid.text.strip()

  def get_cve_debian(self):
    '''Package specific CVE info from https://security-tracker.debian.org '''
    if self.debian_source != '':
      # Use only the first word of a source for lookup
      lookup = self.debian_source.split()[0]
    else:
      lookup = self.package_name
    filename = 'debian_cve/' + lookup + '.html'
    url = 'https://security-tracker.debian.org/tracker/source-package/'+lookup
    if os.path.isfile(filename) == False:
      cache_data(url, filename)
    soup = BeautifulSoup(open(filename))
    cve_numbers = soup.find_all(href=re.compile('CVE-201'))
    self.cve_since_2010 = str(len(cve_numbers))
    self.cve_page = url

  def get_risk_index(self):
    ret = 0
    # If no homepage, add a point
    if len(self.debian_home) == 0 and len(self.openhub_home) == 0:
      self.website_points = 1
    # If implemented in C/C++, add two points
    if self.main_language.upper() in ['C', 'C++'] or self.implemented.upper() in ['C', 'C++']:
      self.language_points = 2
    # Add points depending on number of CVEs
    self.CVE_points = {'0': 0, '1': 1, '2': 2, '3': 2}.get(self.cve_since_2010, 3)
    # Add points depending on number of recent contributors
    self.recent_contributor_points = {'0': 5, '1': 4, '2': 4, '3': 4, '': 2}.\
        get(self.twelve_month_contributor_count, 0)
    # If popular, add 1 point
    if int(self.popularity) >= int(popularity_threshold):
      self.popularity_points = 1
    # If this is data or documentation, deduct 3 points
    if any(role in self.role.lower() for role in ['data', 'documentation']):
      self.data_only_points = -3

    if self.direct_network_exposure == '1':
      self.exposure_points = 2  # Network exposure is weighted more
    elif self.process_network_data == '1':
      self.exposure_points = 1
    elif self.potential_privilege_escalation == '1':
      self.exposure_points = 1
    else:
      self.exposure_points = 0

    ret = self.website_points + self.language_points + self.CVE_points + \
        self.recent_contributor_points + self.popularity_points + \
        self.data_only_points + self.exposure_points

    if ret < 0:
      self.risk_index = '0'
    else:
      self.risk_index = str(ret)


def main():
  global openhub_api_key
  global debian_data
  global debian_pop
  global popularity_threshold

  parser = argparse.ArgumentParser(description='OSS Metrics',
           usage='python program.py -p projects_to_examine.csv')
  parser.add_argument('-p', '--project_file',
                      help='path to csv file with project list', required=True)
  args = parser.parse_args()

  try:
    file = open(args.project_file, 'r')
  except IOError:
    print('Invalid file. Please provide a csv file with projects to examine.')
    sys.exit(1)

  try:
    file = open('openhub_key.txt', 'r')
    openhub_api_key = f.readline().strip()
  except IOError:
    openhub_api_key = ''
    print('[*] No Openhub API key was provided. \
    Will only use cached data (if available).')

  # dict instance with debian data(source, version, description,homepage)
  debian_data = get_debian()
  # dict instance with total installs per package
  debian_pop = get_debian_pop()
  project_name_list = []
  package_list = []

  project_file = open(args.project_file)
  project_reader = csv.reader(project_file, delimiter=',')
  headers = project_reader.next()
  for project_info in project_reader:
    project_name = project_info[headers.index('Debian_Package')].strip()
    if project_name == '':
      continue
    project_name_list.append(project_name)

  # Filter out projects that are not being analyzed from popularity dictionary
  debian_pop = {project_name: debian_pop.get(project_name, 0)
                for project_name in project_name_list}
  # Filter out projects that are not being analyzed from debian dictionary
  debian_data = {project_name: debian_data.get(project_name, {})
                 for project_name in project_name_list}

  popularity_threshold = get_pop_threshold(debian_pop)

  with open(args.project_file) as project_file:
    project_reader = csv.reader(project_file, delimiter=',')
    headers = project_reader.next()
    for project_info in project_reader:
      project_name = project_info[headers.index('Debian_Package')].strip()
      if project_name == '':
        continue
      openhub_name = project_info[headers.index('openhub_name')].strip()
      direct_network_exposure = project_info[headers.index('direct_network_exposure')]
      process_network_data = project_info[headers.index('process_network_data')]
      potential_privilege_escalation = project_info[headers.index('potential_privilege_escalation')]
      comment_on_priority = project_info[headers.index('comment_on_priority')]
      print(project_name)

      Package = Oss_Package(project_name, openhub_name,
                            direct_network_exposure, process_network_data,
                            potential_privilege_escalation, comment_on_priority)

      Package.get_openhub()
      Package.get_cve_debian()
      Package.get_risk_index()
      package_list.append(Package)

  # Sort by risk index
  package_list.sort(key=lambda package: int(package.risk_index), reverse=True)

  # Add the headers row
  with open('results.csv', 'w') as csvfile:
    headerwriter = csv.writer(csvfile, delimiter=',')
    headerwriter.writerow(['project_name', 'debian_source', 'debian_version',
          'debian_desc', 'debian_home', 'CVE_since_2010', 'CVE_page', 'openhub_page',
          'openhub_name', 'openhub_desc', 'openhub_home', 'openhub_download',
          'twelve_month_contributor_count', 'total_contributor_count', 'total_code_lines',
          'main_language_name', 'licenses', 'fact_activity', 'fact_age', 'fact_comments',
          'fact_team_size', 'package_popularity', 'implemented_in', 'role',
          'direct_network_exposure', 'process_network_data', 'potential_privilege_escalation',
          'risk_index(max = 16)', 'risk_index components', 'comment_on_priority'])

  csvfile = open('results.csv', 'a')
  resultwriter = csv.writer(csvfile, delimiter=',')
  # Write each package results into csv
  for p in package_list:
    row = [p.package_name, p.debian_source, p.debian_version,
           p.debian_desc, p.debian_home, p.cve_since_2010, p.cve_page,  p.openhub_page,
           p.openhub_name, p.openhub_desc, p.openhub_home, p.openhub_download,
           p.twelve_month_contributor_count, p.total_contributor_count, p.total_code_lines,
           p.main_language, p.licenses, p.fact_activity, p.fact_age, p.fact_comments,
           p.fact_team_size, p.popularity, p.implemented,p.role,
           p.direct_network_exposure, p.process_network_data, p.potential_privilege_escalation,
           p.risk_index, 'Website points: ' + str(p.website_points) +
           ', CVE: ' + str(p.CVE_points) + ', 12-month contributor: ' +
           str(p.recent_contributor_points) + ', Popularity: ' + str(p.popularity_points) +
           ', Language: ' + str(p.language_points) + ', Exposure: ' + str(p.exposure_points) +
           ' , Data only: ' + str(p.data_only_points), p.comment_on_priority]

    resultwriter.writerow(remove_non_ascii(row))

if __name__ == "__main__":
  main()
