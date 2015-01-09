#!/usr/bin/python
''' Copyright (c) 2012 Cloudera, Inc. All rights reserved.
    Sample script for Nagios integration with Cloudera Manager via the CM API.
'''

import sys
import optparse
import tempfile
from os import getcwd, devnull
from os.path import join, isfile
from subprocess import call
from time import sleep, time
from urllib2 import quote

from cm_api.api_client import get_root_resource, ApiException
import cm_api.endpoints.clusters
import cm_api.endpoints.hosts
import cm_api.endpoints.services
import cm_api.endpoints.roles

CM_API_VERSION = 6

def parse_args():
  ''' Parse the script arguments
  '''
  parser = optparse.OptionParser()

  parser.add_option("-v", "--verbose", action="store_true")

  general_options = optparse.OptionGroup(parser, "CM API Configuration")
  general_options.add_option("-H", "--host", metavar="HOST",
                             help="CM API hostname")
  general_options.add_option("-p", "--port", help="CM API port", default=None)
  general_options.add_option("-P", "--passfile", metavar="FILE",
                             help="File containing CM API username and password, "
                                  "colon-delimited on a single line.  E.g. "
                                  "\"user:pass\"")
  general_options.add_option("--use-tls", action="store_true",
                             help="Use TLS", default=False)
  parser.add_option_group(general_options)
  (options, args) = parser.parse_args()

  ''' Parse the 'passfile' - it must contain the username and password,
      colon-delimited on a single line. E.g.:
      $ cat ~/protected/cm_pass
      admin:admin
  '''
  required = ["host", "passfile"]
  for required_opt in required:
    if getattr(options, required_opt) is None:
      parser.error("Please specify the required argument: --%s" %
                   (required_opt.replace('_','-'),))

  return (options, args)


def get_host_map(root):
  ''' Gets a mapping between CM hostId and Nagios host information

      The key is the CM hostId
      The value is an object containing the Nagios hostname and host address
  '''
  hosts_map = {}
  for host in root.get_all_hosts():
    hosts_map[host.hostId] = {"hostname": NAGIOS_HOSTNAME_FORMAT % (host.hostname,),
                              "address": host.ipAddress}

  ''' Also define "virtual hosts" for the CM clusters- they will be the hosts
      to which CM services are mapped
  '''
  for cluster in root.get_all_clusters():
    hosts_map[cluster.name] = {"hostname": cluster.name,
                               "address": quote(cluster.name)}
  hosts_map[CM_DUMMY_HOST] = {"hostname": CM_DUMMY_HOST,
                              "address": CM_DUMMY_HOST}
  return hosts_map


def get_status(api_subject):
  ''' Gets a string representing the status of the Api subject (role or service)
      based on the health summary and health checks.
  '''
  summary = api_subject.healthSummary
  if summary is None:
    return None
  # status string always starts with "<nagios code>: <summary>"
  status = "%s: %s" % (NAGIOS_CODE_MESSAGES[CM_STATE_CODES[summary]], summary)
  if summary != "GOOD" and summary != "DISABLED":
    # if the summary is CONCERNING or BAD, then append the health checks
    for health_check in api_subject.healthChecks:
      if health_check['summary'] != "GOOD" and health_check['summary'] != "DISABLED":
        status = ("%s, %s=%s" % (status, health_check['name'], health_check['summary']))
  return status

def get_services(root, hosts_map, view=None):
  ''' Gets a list of objects representing the Nagios services.

      Each object contains the Nagios hostname, service name, service display
      name, and service health summary.
  '''
  services_list = []
  mgmt_service = root.get_cloudera_manager().get_service()
  services_list.append({"hostname": CM_DUMMY_HOST,
                        "name": mgmt_service.name,
                        "display_name": "CM Managed Service: %s" % (mgmt_service.name,),
                        "status": get_status(mgmt_service),
                        "url": mgmt_service.serviceUrl,
                        "health_summary": mgmt_service.healthSummary})
  for cm_role in root.get_cloudera_manager().get_service().get_all_roles(view):
    services_list.append({"hostname": hosts_map[cm_role.hostRef.hostId]["hostname"],
                          "name": cm_role.name,
                          "display_name": "CM Management Service: %s" % (cm_role.name,),
                          "status": get_status(cm_role),
                          "url": cm_role.roleUrl,
                          "health_summary": cm_role.healthSummary})
  for cm_host in root.get_all_hosts(view):
    services_list.append({"hostname": hosts_map[cm_host.hostId]["hostname"],
                          "name": "cm-host-%s" % (cm_host.hostname,),
                          "display_name": "CM Managed Host: %s" % (cm_host.hostname,),
                          "status": get_status(cm_host),
                          "url": cm_host.hostUrl,
                          "health_summary": cm_host.healthSummary})
  for cluster in root.get_all_clusters(view):
    for service in cluster.get_all_services(view):
      services_list.append({"hostname": cluster.name,
                            "name": service.name,
                            "display_name": "CM Managed Service: %s" % (service.name,),
                            "status": get_status(service),
                            "url": service.serviceUrl,
                            "health_summary": service.healthSummary})
      for role in service.get_all_roles(view):
        services_list.append({"hostname": hosts_map[role.hostRef.hostId]["hostname"],
                              "name": role.name,
                              "display_name": "%s:%s" % (cluster.name, role.name,),
                              "status": get_status(role),
                              "url": role.roleUrl,
                              "health_summary": role.healthSummary})
  return services_list

def main():
  (options, args) = parse_args()

  try:
    (username, password) = open(options.passfile, 'r').readline().rstrip('\n').split(':')
  except:
    print >> sys.stderr, "Unable to read username and password from file '%s'. "
    "Make sure the file is readable and contains a single line of "
    "the form \"<username>:<password>\"" % options.passfile

  root = get_root_resource(options.host, options.port, username,
                           password, options.use_tls, CM_API_VERSION)
  clusters = root.get_all_clusters()
  for cluster in clusters:
      host_refs = cluster.list_hosts()
      services  = cluster.get_all_services()

      print "# Cluster Summary #"
      print "Name: %s" % cluster.displayName
      print "Number of hosts: %d" % len(host_refs)
      print "Number of services: %d" % len(services)

      print "## Host Summary"
      for ref in host_refs:
          host = root.get_host(ref.hostId)
          print "Host: %(host)s, Health Summary: %(health)s" % {
             'host': host.hostname
           , 'health': host.healthSummary
          }

      print "## Host Health Checks"
      for ref in host_refs:
          host = root.get_host(ref.hostId)
          checks = host.healthChecks
          for check in checks:
              print "Host: %(host)s, Health Check: %(health)s, Status: %(status)s" % {
                'host': host.hostname
              , 'health': check['name']
              , 'status': check['summary']
              }

      print "## Service Summary"
      for service in services:
        print "Service: %(name)s, Health Summary: %(health)s" % {
           'name': service.displayName
         , 'health': service.healthSummary
        }
        for check in service.healthChecks:
            print "Service: %(name)s, Health Check: %(health)s, Status: %(status)s" % {
                'name': service.displayName
              , 'health': check['name']
              , 'status': check['summary']
            }
        for role in service.get_all_roles():
            print "Service: %(service_name)s, Role: %(role_name)s, Health Summary: %(health)s" % {
                'service_name': service.displayName
              , 'role_name': role.name
              , 'health': role.healthSummary
            }
            for check in role.healthChecks:
                print "Service: %(service_name)s, Role: %(role_name)s, Health Check: %(health)s, Status: %(status)s" % {
                    'service_name': service.displayName
                  , 'role_name': role.name
                  , 'health': check['name']
                  , 'status': check['summary']
                }

  sys.exit(0)

if __name__ == "__main__":
  main()
