#!/usr/bin/env python
"""
CGNX Get Site info for all sites.

tanushree@cloudgenix.com

"""
# standard modules
import argparse
import getpass
import json
import logging
import requests
import datetime
import os
import sys
import progressbar
from progressbar import Bar, ETA, Percentage, ProgressBar

# standard modules
import argparse
import json
import logging

# CloudGenix Python SDK
import cloudgenix

# Global Vars
TIME_BETWEEN_API_UPDATES = 60       # seconds
REFRESH_LOGIN_TOKEN_INTERVAL = 7    # hours
SDK_VERSION = cloudgenix.version
SCRIPT_NAME = 'CloudGenix Get Site Info -> CSV Generator'


# Set NON-SYSLOG logging to use function name
logger = logging.getLogger(__name__)

CSVHEADER = 'Site Name,Admin State,Element Cluster Role,Policy Set(v1),Security Policy Set,Network_PolicySet_Stack,Priority_PolicySet_Stack,Address:Street,Address:Street2,Address:City,Address:Postal Code, Address:Country,Latitude,Longitude,Tags\n'



nwstackid_nwstackname_dict = {}
qosstackid_qosstackname_dict = {}
secpolid_secpolname_dict = {}
polid_polname_dict = {}


def createdicts(cgx_session):

    # Network Stack
    resp = cgx_session.get.networkpolicysetstacks()
    if resp.cgx_status:
        nwstacklist = resp.cgx_content.get("items",None)
        for nwstack in nwstacklist:
            nwstackid_nwstackname_dict[nwstack['id']] = nwstack['name']

    else:
        print("ERR: Could not query Network Policy Stack")
        cloudgenix.jd_detailed(resp)


    # QoS Stack
    resp = cgx_session.get.prioritypolicysetstacks()
    if resp.cgx_status:
        qosstacklist = resp.cgx_content.get("items", None)
        for qosstack in qosstacklist:
            qosstackid_qosstackname_dict[qosstack['id']] = qosstack['name']

    else:
        print("ERR: Could not query Priority Policy Stack")
        cloudgenix.jd_detailed(resp)


    # Policy (v1)
    resp = cgx_session.get.policysets()
    if resp.cgx_status:
        pollist = resp.cgx_content.get("items", None)

        for pol in pollist:
            polid_polname_dict[pol['id']] = pol['name']

    else:
        print("ERR: Could not query for Policy Sets (v1)")
        cloudgenix.jd_detailed(resp)


    # Security Set
    resp = cgx_session.get.securitypolicysets()
    if resp.cgx_status:
        secpollist = resp.cgx_content.get("items", None)

        for secpol in secpollist:
            secpolid_secpolname_dict[secpol['id']] = secpol['name']

    else:
        print("ERR: Could not query for Security Policy Sets")
        cloudgenix.jd_detailed(resp)


    return



def get_site_info(cgx_session, site_csv):
    """
    Gets site info across tenant and populate CSV with info
    :param cgx_session: cgx_session global info struct
    """

    # Retrieve Element info
    site_response = cgx_session.get.sites()
    site_list = site_response.cgx_content.get('items', None)

    if not site_response.cgx_status or not site_list:
        logger.info("ERROR: unable to get sites for account '{0}'.".format(cgx_session.tenant_name))
        return

    bar = len(site_list) + 1
    barcount = 1

    #could be a long query - start a progress bar.
    pbar = ProgressBar(widgets=[Percentage(), Bar(), ETA()],max_value = bar).start()


    # print "Getting WAN NEtworks"
    # wannetworks_response = cgx_session.get.wannetworks()
    # print json.dumps(wannetworks_response.cgx_content, indent=4)


    # build translation dict
    for site in site_list:
        #print json.dumps(site, indent=4)
        site_name = "\""+site.get('name')+"\""

        site_id = site.get('id')

        admin_state = site.get('admin_state')
        element_cluster_role = site.get('element_cluster_role')

        network_policyset_id = site.get('policy_set_id')
        if network_policyset_id in polid_polname_dict.keys():
            networkpolicyset_name = polid_polname_dict[network_policyset_id]
        else:
            networkpolicyset_name = None

        security_policyset_id = site.get('security_policyset_id')
        if security_policyset_id in secpolid_secpolname_dict.keys():
            securitypolicyset_name = secpolid_secpolname_dict[security_policyset_id]
        else:
            securitypolicyset_name = None

        network_policysetstack_id = site.get('network_policysetstack_id')
        if network_policysetstack_id in nwstackid_nwstackname_dict.keys():
            networkpolicysetstack_name = nwstackid_nwstackname_dict[network_policysetstack_id]
        else:
            networkpolicysetstack_name = None

        qos_policysetstack_id = site.get('priority_policysetstack_id')
        if qos_policysetstack_id in qosstackid_qosstackname_dict.keys():
            prioritypolicysetstack_name = qosstackid_qosstackname_dict[qos_policysetstack_id]
        else:
            prioritypolicysetstack_name = None


        address = site.get('address', None)
        if address:
            if address['street'] is not None:
                street = "\""+address['street']+"\""
            else:
                street = address['street']


            if address['street2'] is not None:
                street2 = "\""+address['street2']+"\""
            else:
                street2 = address['street2']

            city = address['city']
            post_code = address['post_code']
            country = address['country']
        else:
            street = "n/a"
            street2 = "n/a"
            city = "n/a"
            post_code = "n/a"
            country = "n/a"

        location = site.get('location',None)
        if location:
            latitude = location['latitude']
            longitude = location['longitude']
        else:
            latitude = "n/a"
            longitude = "n/a"

        tags = site.get('tags', None)
        if tags is not None:
            tagnames = " ".join(tags)
        else:
            tagnames = None


        write_to_csv(site_csv, site_name, admin_state, element_cluster_role, networkpolicyset_name, securitypolicyset_name,  networkpolicysetstack_name, prioritypolicysetstack_name, street, street2, city, post_code, country, latitude, longitude, tagnames)

        barcount += 1
        pbar.update(barcount)

    # finish after iteration.
    pbar.finish()

    return


def write_to_csv(csv_file_name, site_name="", admin_state="", element_cluster_role="", network_policyset="", security_policyset="",networkstack="",prioritystack="",street="", street2="", city="", post_code="", country="", latitude="", longitude="", tags=""):
    # global variable write.
    write_str = '{0},{1},{2},{3},{4},{5},{6},{7},{8},{9},{10},{11},{12},{13},{14}\n'\
                .format(
                    # Site Name
                    site_name,
                    # Admin State
                    admin_state,
                    # Element Cluster Role
                    element_cluster_role,
                    # Network Policyset
                    network_policyset,
                    # Security Policyset
                    security_policyset,
                    # Network Stack
                    networkstack,
                    # Priority Stack
                    prioritystack,
                    # Address
                    street,
                    street2,
                    city,
                    post_code,
                    country,
                    # Location
                    latitude,
                    longitude,
                    tags,
                )

    with open(csv_file_name, 'a') as csv_file:
        csv_file.write(write_str)
        csv_file.flush()

    return

def go():
    ############################################################################
    # Begin Script, parse arguments.
    ############################################################################

    # Parse arguments
    parser = argparse.ArgumentParser(description="{0}.".format(SCRIPT_NAME))

    # Allow Controller modification and debug level sets.
    controller_group = parser.add_argument_group('API', 'These options change how this program connects to the API.')
    controller_group.add_argument("--controller", "-C",
                                  help="Controller URI, ex. https://cloudgenix.com:8443",
                                  default=None)

    controller_group.add_argument("--insecure", "-I", help="Disable SSL certificate and hostname verification",
                                  dest='verify', action='store_false', default=True)

    login_group = parser.add_argument_group('Login', 'These options allow skipping of interactive login')
    login_group.add_argument("--email", "-E", help="Use this email as User Name instead of prompting",
                             default=None)
    login_group.add_argument("--pass", "-PW", help="Use this Password instead of prompting",
                             default=None)

    debug_group = parser.add_argument_group('Debug', 'These options enable debugging output')
    debug_group.add_argument("--debug", "-D", help="Verbose Debug info, levels 0-2", type=int,
                             default=0)

    args = vars(parser.parse_args())

    if args['debug'] == 1:
        logging.basicConfig(level=logging.INFO,
                            format="%(levelname)s [%(name)s.%(funcName)s:%(lineno)d] %(message)s")
        logger.setLevel(logging.INFO)
    elif args['debug'] >= 2:
        logging.basicConfig(level=logging.DEBUG,
                            format="%(levelname)s [%(name)s.%(funcName)s:%(lineno)d] %(message)s")
        logger.setLevel(logging.DEBUG)
    else:
        # Remove all handlers
        for handler in logging.root.handlers[:]:
            logging.root.removeHandler(handler)
        # set logging level to default
        logger.setLevel(logging.WARNING)

    ############################################################################
    # Instantiate API
    ############################################################################
    cgx_session = cloudgenix.API(controller=args["controller"], ssl_verify=args["verify"])

    # set debug
    cgx_session.set_debug(args["debug"])

    ##
    # ##########################################################################
    # Draw Interactive login banner, run interactive login including args above.
    ############################################################################

    print("{0} v{1} ({2})\n".format(SCRIPT_NAME, SDK_VERSION, cgx_session.controller))

    # interactive or cmd-line specified initial login

    while cgx_session.tenant_name is None:
        cgx_session.interactive.login(args["email"], args["pass"])

    ############################################################################
    # End Login handling, begin script..
    ############################################################################

    # get time now.
    curtime_str = datetime.datetime.utcnow().strftime('%Y-%m-%d-%H-%M-%S')

    # create file-system friendly tenant str.
    tenant_str = "".join(x for x in cgx_session.tenant_name if x.isalnum()).lower()

    # Set filenames
    site_csv = os.path.join('./', '%s_site_info_%s.csv' %
                                  (tenant_str, curtime_str))

    print("Creating %s for data output..." % (str(site_csv)))
    with open(site_csv, 'w') as csv_file:
        csv_file.write(CSVHEADER)
        csv_file.flush()

    # Create Translation Dicts
    createdicts(cgx_session)
    get_site_info(cgx_session, site_csv)

    # end of script, run logout to clear session.
    cgx_session.get.logout()

    print("Logging Out.")


if __name__ == "__main__":
    go()
