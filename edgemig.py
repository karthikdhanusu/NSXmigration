                                                #####################################################################
                                                #                                                                   #
                                                #       Project: NSX Migration Tool                                 #
                                                # 1. NSX edge firewall, NAT, DHCP, IPsec Sites, Grouping Objects.   #
                                                # 2. NSX Security groups and its corresponding Security policies.   #
                                                # 3. NSX Distributed firewall rules                                 #
                                                #                                                                   #
                                                # Author: Karthik Dhanusu                                           #
                                                #                                                                   #
                                                #                                                                   #
                                                #####################################################################

import requests
from requests.auth import HTTPBasicAuth
import getpass
from xml.etree import ElementTree as ET
from lxml import etree
from pyVim import connect
from pyVmomi import vim
import os
import time



 ## URL definitions ##

edgeget = '/4.0/edges'
vdnscopes = '/2.0/vdn/scopes'
virtualwires = '/virtualwires'
application = '/2.0/services/application'
applicationgroup = '/2.0/services/applicationgroup'
ipset = '/2.0/services/ipset'
virtwire = '/2.0/vdn/virtualwires'
fwconfig = '/firewall/config'
natconfig = '/nat/config'
natconfigrules = '/nat/config/rules'
dhcpconfig = '/dhcp/config'
dhcprelay = '/dhcp/config/relay'
dhcppool = '/dhcp/config/ippools'
ipsec = '/ipsec/config'
dfwexport = '/4.0/firewall/globalroot-0/drafts'
dfwdfltconfig = '/4.0/firewall/globalroot-0/defaultconfig'
dfwconfig = '/4.0/firewall/globalroot-0/config'
dfwl3 = '/4.0/firewall/globalroot-0/config/layer3sections'
dfwl2 = '/4.0/firewall/globalroot-0/config/layer2sections'
dfwl3rs = '/4.0/firewall/globalroot-0/config/layer3redirectsections'
dfwstatus = '/4.0/firewall/globalroot-0/status'
sg = '/2.0/services/securitygroup/scope/'
getojid = '/2.0/services/securitygroup/'
sgpost = '/2.0/services/securitygroup/bulk/'
spfwget = '/2.0/services/policy/securitypolicy/serviceprovider/firewall/'
scconfig = '/2.0/services/policy/securitypolicy/hierarchy'
scpl = '/2.0/services/policy/securitypolicy'


def banner(text, ch='#', length=100):
    spaced_text = ' %s ' % text
    banner = spaced_text.center(length, ch)
    return banner

def userinput():                #user input
    os.system('cls')
    pullbanner = banner(text='NSX DFW, Edge gateway and its services migration tool')
    print(pullbanner)
    print("")
    print("## Instructions: ##")
    print("====================")
    print("1. Please create all the required gateways before proceeding for other config migrations")
    print("2. The script will automatically creates grouping objects and all the required security groups")
    print("3. The script will re-map all the grouping objects and the security groups, if any associated with the firewall rules")
    print("4. If the vSphere objects doesn't exist in the destination environment, the script will exclude the associated objects")
    print("5. End user will be presented with the list of vSphere Objects that are not avaiable at the destination side ")
    print("6. End-user will be presented with the list of edge and distributed firewall rules that needs manual intervention")
    print("7. Some of the rules may not have vSphere object association as the some of them may not be present at the destination side")
    print("")
    global sourcevc, sourcevcun, sourcevcpss, sourcepcc,sourceun, sourcepss, sport, destvc, destvcun, destvcpss, destpcc, destun, destpass, dport, nsx_sbaseurl, nsx_dbaseurl
    sourcevc = input('Enter Source vCenter Hostname/IP:')
    sourcevcun = input('Enter Source vCenter UserName:')
    sourcevcpss = getpass.getpass(prompt='Enter Source vCenter Password:')
    sourcepcc = input('Enter Source NSX Hostname/IP:')
    sourceun = input('Enter Source NSX UserName:')
    sourcepss = getpass.getpass(prompt='Enter Source vCenter Password:')
    sport = 443
    destvc = input('Enter Destination vCenter Hostname/IP:')
    destvcun = input('Enter Destination  vCenter UserName:')
    destvcpss = getpass.getpass(prompt='Enter Destination vCenter Password:')
    destpcc = input('Enter Destination NSX Hostname/IP:')
    destun = input('Enter Destination NSX UserName:')
    destpass = getpass.getpass(prompt='Enter Destination vCenter Password:')
    dport = 443
    nsx_sbaseurl = 'https://' + sourcepcc + '/api'
    nsx_dbaseurl = 'https://' + destpcc + '/api'
    os.system('cls')
    pullbanner = banner(text='NSX DFW, Edge gateway and its services migration tool')
    print(pullbanner)
    print("")
    print("Select the NSX Object Type:")
    print("1.Edge Gateway & Services")
    print("2.Security groups")
    print("3.Distributed firewall Configs ")
    objtype = int(input('Enter your choice [1-3]:'))
    objecttype(objtype)


def objecttype(objtype):   #type selection
    if objtype == 1:
        os.system('cls')
        print("## List of Edge gateways at source, Please select the corresponding values from the below key-Value pair ##")
        print("")
        print(getedges())
        global edgeid
        print("")
        edgeid = input('Select an Edge-ID to migrate it to the destination:')
        os.system('cls')
        print("Edge Password Requirements:")
        print("===========================")
        print("1.Password length must be at 12 Characters and at-Max 255Characters")
        print("2.Password must contain mix of atleast one upper case, lower case, number & special characters")
        print("3.Password must not contain username as substring")
        print("")
        edgpass = getpass.getpass(prompt='Please enter the CLI password for the new edge :')
        getedge(edgeid, edgpass)
    elif objtype == 2:
        os.system('cls')
        sgcrte()
        spcrte()
    elif objtype == 3:
        os.system('cls')
        dfw()


                # get destination transport zone

def getvdn():
    vdn={}
    vdnurl = nsx_dbaseurl+vdnscopes
    vdnreq = requests.get(vdnurl, headers={'Content-Type': 'application/*+xml;version=5.7'},auth=HTTPBasicAuth(destun, destpass))
    cont = vdnreq.content
    xml = ET.fromstring(cont)
    for child in xml.findall('vdnScope'):
        vdnid = child.find('objectId').text
        vdnname = child.find('name').text
        vdn.update({vdnname:vdnid})
    return vdn

                    # get virtual wires from a specific TZ

def vdnls(dvdn):
    vdls = {}
    vdnlsurl = nsx_dbaseurl+vdnscopes+'/'+dvdn+virtualwires
    vdnlsreq = requests.get(vdnlsurl, headers={'Content-Type': 'application/*+xml;version=5.7'},auth=HTTPBasicAuth(destun, destpass))
    cont = vdnlsreq.content
    xml = ET.fromstring(cont)
    for child in xml.findall('.//virtualWire'):
        if child.find('name') != None:
            lsname = child.find('name').text
            lsid = child.find('objectId').text
            vdls.update({lsname:lsid})
    return vdls

                            #get Moref of vSphere Objects from Destination vCenter

def moid(viewType, host, user, pwd, port, dcmoid):
    moidu = {}
    service_instance = connect.SmartConnect(host=host,
                                            user=user,
                                            pwd=pwd,
                                            port=port)
    content = service_instance.RetrieveContent()
    if viewType == [vim.Datacenter]:
        container = content.rootFolder
        recursive = True  # whether we should look into it recursively
        containerView = content.viewManager.CreateContainerView(container, viewType, recursive)
        children = containerView.view
        for child in children:
            try:
                mid = str(child)
            except IndexError:
                pass
            moid = mid[mid.find(":") + 1:-1]
            moidu.update({child.name: moid})
        return moidu
    elif viewType == [vim.Folder]:
        container = content.rootFolder  # starting point to look into
        recursive = True  # whether we should look into it recursively
        containerView = content.viewManager.CreateContainerView(container, viewType, recursive)
        children = containerView.view
        for child in children:
            try:
                foldobj = str(child.childType[1])
            except IndexError:
                pass
            if foldobj == 'VirtualMachine':
                mid = str(child)
                moid = mid[mid.find(":") + 1:-1]
                moidu.update({child.name: moid})
        return moidu
    else:
        container = content.rootFolder.childEntity# starting point to look into
        for i in range(0,len(container)):
            contobj = str(container[i])#[container[i].find(":"):]
            containerobj = contobj[contobj.find(":")+1:-1]
            if dcmoid == containerobj:
                object = content.rootFolder.childEntity[i]
                recursive = True  # whether we should look into it recursively
                containerView = content.viewManager.CreateContainerView(
                            object, viewType, recursive)
                children = containerView.view
                for child in children:
                    try:
                        mid = str(child)
                    except IndexError:
                        pass
                    moid = mid[mid.find(":") + 1:-1]
                    moidu.update({child.name:moid})
                return moidu

                    # get Moref of vSphere Objects from Source vCenter

def smoid(viewType, host, user, pwd, port):
    moidu = {}
    service_instance = connect.SmartConnect(host=host,
                                            user=user,
                                            pwd=pwd,
                                            port=port)
    content = service_instance.RetrieveContent()
    container = content.rootFolder
    recursive = True  # whether we should look into it recursively
    containerView = content.viewManager.CreateContainerView(
        container, viewType, recursive)
    children = containerView.view
    for child in children:
        try:
            mid = str(child)
        except IndexError:
            pass
        moid = mid[mid.find(":") + 1:-1]
        moidu.update({child.name: moid})
    return moidu

                        #get instanceUUId for all the virtual machines

def vmid(viewType, host, user, pwd, port):
    moidu = {}
    service_instance = connect.SmartConnect(host=host,
                                            user=user,
                                            pwd=pwd,
                                            port=port)
    content = service_instance.RetrieveContent()
    container = content.rootFolder
    recursive = True  # whether we should look into it recursively
    containerView = content.viewManager.CreateContainerView(
        container, viewType, recursive)
    children = containerView.view
    for child in children:
        vmnme = child.summary.config.name
        instid = child.summary.config.instanceUuid
        moidu.update({vmnme: instid})
    return moidu


                                # Get list of edges from source NSX in key-value pair

def getedges():
    getedges = nsx_sbaseurl+edgeget
    edgereq = requests.get(getedges, headers = {'Content-Type': 'application/*+xml;version=5.7'}, auth=HTTPBasicAuth(sourceun, sourcepss))
    cont = edgereq.content
    # get edge names
    xml = ET.fromstring(cont)
    objectId = {}
    for child in xml.findall('.//edgeSummary'):
        edgnme = child.find('name').text
        edgid = child.find('objectId').text
        objectId.update({edgnme: edgid})
    return objectId

                            # Get list of edges from destination NSX in key-value pair

def getdedges():
    getedges = nsx_dbaseurl+edgeget
    edgereq = requests.get(getedges, headers = {'Content-Type': 'application/*+xml;version=5.7'}, auth=HTTPBasicAuth(destun, destpass))
    cont = edgereq.content
    # get edge names
    xml = ET.fromstring(cont)
    dobjectId = {}
    for child in xml.findall('.//edgeSummary'):
        edgnme = child.find('name').text
        edgid = child.find('objectId').text
        dobjectId.update({edgnme:edgid})
    return dobjectId

                        #get list of logical switches from source NSX

def getsls():
    sls = {}
    lsurl = nsx_sbaseurl + virtwire+'?pagesize=1024'
    lsreq = requests.get(lsurl, headers = {'Content-Type': 'application/*+xml;version=5.7'}, auth=HTTPBasicAuth(sourceun, sourcepss))
    cont = lsreq.content
    xml = etree.fromstring(cont)
    for child in xml.findall('.//virtualWire'):
        sls.update({child.find('name').text:child.find('objectId').text})
    return sls

                        ##get list of logical switches from destination NSX

def getdls():
    dls = {}
    lsurl = nsx_dbaseurl + virtwire+'?pagesize=1024'
    lsreq = requests.get(lsurl, headers = {'Content-Type': 'application/*+xml;version=5.7'}, auth=HTTPBasicAuth(destun, destpass))
    cont = lsreq.content
    xml = etree.fromstring(cont)
    for child in xml.findall('.//virtualWire'):
        dls.update({child.find('name').text:child.find('objectId').text})
    return dls

                        # get ipsets from source NSX

def getsipsets():
    sips = {}
    ipsurl = nsx_sbaseurl + ipset + '/scope/globalroot-0'
    ipsreq = requests.get(ipsurl, headers = {'Content-Type': 'application/*+xml;version=5.7'}, auth=HTTPBasicAuth(sourceun, sourcepss))
    cont = ipsreq.content
    xml = etree.fromstring(cont)
    for child in xml.findall('.//ipset'):
        sips.update({child.find('name').text: child.find('objectId').text})
    return sips

                        # get ipsets from destination NSX

def getdipsets():
    dips = {}
    ipsurl = nsx_dbaseurl + ipset + '/scope/globalroot-0'
    ipsreq = requests.get(ipsurl, headers = {'Content-Type': 'application/*+xml;version=5.7'}, auth=HTTPBasicAuth(destun, destpass))
    cont = ipsreq.content
    xml = etree.fromstring(cont)
    for child in xml.findall('.//ipset'):
        dips.update({child.find('name').text: child.find('objectId').text})
    return dips

                        # create logical switch under a TZ

def crtels(lsnme, dvdn):
    xmlhead = '<?xml version="1.0" encoding="UTF-8"?>'
    lsxml = '<virtualWireCreateSpec><name>'+lsnme+'</name><tenantId>Default vxLan of Datacenter</tenantId><controlPlaneMode>UNICAST_MODE</controlPlaneMode><guestVlanAllowed>false</guestVlanAllowed></virtualWireCreateSpec>'
    lsbody = xmlhead+lsxml
    lsurl = nsx_dbaseurl + vdnscopes + '/' + dvdn + virtualwires
    lsreq = requests.post(lsurl, data=lsbody, headers={'Content-Type': 'application/xml'}, auth=HTTPBasicAuth(destun, destpass))
    vwire = lsreq.content.decode()
    return vwire

                        # Create an edge gateway

def getedge(edgeid, edgpass):
    global dcmoid
    vdn = getvdn()
    xmlhead = '<?xml version="1.0" encoding="UTF-8"?>'
    lsxml = '<virtualWireCreateSpec><name>ls[i]</name><tenantId>Default vxLan of Datacenter</tenantId><controlPlaneMode>UNICAST_MODE</controlPlaneMode><guestVlanAllowed>false</guestVlanAllowed></virtualWireCreateSpec>'
    getedges = nsx_sbaseurl+edgeget+'/'+edgeid
    edgereq = requests.get(getedges, headers={'Content-Type': 'application/*+xml;version=5.7'},auth=HTTPBasicAuth(sourceun, sourcepss))
    cont = edgereq.content
    xml = etree.fromstring(cont)
    os.system('cls')
    print("Destination side Datacenters to place the new edge:")
    print("")
    print(moid(viewType=[vim.Datacenter], host=destvc, user=destvcun, pwd=destvcpss, port=dport, dcmoid=None))
    print("")
    print("Objects shown above are Key Value pair, Please use the value corresponding to the key to select")
    dcmoid = input('Select a Datacenter ID for the new edge:')
    dmoid = '<datacenterMoid>' + dcmoid + '</datacenterMoid>' #'<datacenterMoid>' + 'datacenter-120' + '</datacenterMoid>'
    os.system('cls')
    print("Destination side Resource pools to place the new edge:")
    print("")
    print(moid(viewType=[vim.ResourcePool], host=destvc, user=destvcun, pwd=destvcpss, port=dport, dcmoid=dcmoid))
    print("")
    print("Objects shown above are Key Value pair, Please use the value corresponding to the key to select")
    rsmoid = input('Select a Resourcepool ID for the new edge:')
    apprsid =  '<resourcePoolId>'+rsmoid+'</resourcePoolId>'        #'<resourcePoolId>'+'resgroup-135'+'</resourcePoolId>'
    os.system('cls')
    print("Destination side Datastores to place the new edge:")
    print("")
    print(moid(viewType=[vim.Datastore], host=destvc, user=destvcun, pwd=destvcpss, port=dport, dcmoid=dcmoid))
    print("")
    print("Objects shown above are Key Value pair, Please use the value corresponding to the key to select")
    smoid = input('Select a Datastore ID for the new edge:')
    appdsid =  '<datastoreId>'+smoid+'</datastoreId>' #'<datastoreId>'+'datastore-90'+'</datastoreId>'
    os.system('cls')
    print("Destination side Hostsystems to place the new edge:")
    print("")
    print(moid(viewType=[vim.HostSystem], host=destvc, user=destvcun, pwd=destvcpss, port=dport, dcmoid=dcmoid))
    print("")
    print("Objects shown above are Key Value pair, Please use the value corresponding to the key to select")
    hmoid = input('Select a Host ID for the new edge:')
    apphid =  '<hostId>'+hmoid+'</hostId>'  #'<hostId>'+'host-94'+'</hostId>'
    os.system('cls')
    print("Destination side Folders to place the new edge:")
    print("")
    print(moid(viewType=[vim.Folder], host=destvc, user=destvcun, pwd=destvcpss, port=dport, dcmoid=None))
    print("")
    print("Objects shown above are Key Value pair, Please use the value corresponding to the key to select")
    fdmoid = input('Select a Folder ID for the new edge:')
    appvid =  '<vmFolderId>'+fdmoid+'</vmFolderId>' #'<vmFolderId>'+'group-v134'+'</vmFolderId>'
    os.system('cls')
    tenant = xml.xpath('//tenant')
    name = xml.xpath('//edge/name')
    enableAesni = xml.xpath('//enableAesni')
    enableFips = xml.xpath('//enableFips')
    vseLogLevel = xml.xpath('//vseLogLevel')
    appliancesize = xml.xpath('//appliances/applianceSize')
    appcpures = xml.find('.//appliances/appliance/cpuReservation')
    appmemres = xml.find('.//appliances/appliance/memoryReservation')
    tenantb = (b''.join(map(etree.tostring, tenant))).strip().decode()
    nameb = (b''.join(map(etree.tostring, name))).strip().decode()
    enableAesni = (b''.join(map(etree.tostring, enableAesni))).strip().decode()
    enableFips = (b''.join(map(etree.tostring, enableFips))).strip().decode()
    vseLogLevel = (b''.join(map(etree.tostring, vseLogLevel))).strip().decode()
    appliancesizeb = (b''.join(map(etree.tostring, appliancesize))).strip().decode()
    appcpub = (b''.join(map(etree.tostring, appcpures))).strip().decode()
    appmemb = (b''.join(map(etree.tostring, appmemres))).strip().decode()
    ls = []
    dls = {}
    for child in xml.findall('.//vnics/vnic/portgroupName'):
        ls.append(child.text)
    lsno = len(ls)
    print("Destination side Transport Zones to create logical switches for edge interface mapping:")
    print("")
    print(vdn)
    print("Objects shown above are Key Value pair, Please use the value corresponding to the key to select")
    dvdn = input("select the Transport zone to create Logical switches:")
    os.system('cls')
    print("##-- Re-mapping the networks on interfaces to suit the destination Environment --##")
    vdls = vdnls(dvdn)
    for i in range(0,lsno):
        if ls[i] not in vdls.keys():
            lsnme = ls[i]
            if lsnme != 'VM Network':
                virtwire = crtels(lsnme, dvdn)
                dls.update({lsnme:virtwire})
                i +=1
            elif lsnme == 'VM Network':
                dpg = moid(viewType=[vim.Network], host=destvc, user=destvcun, pwd=destvcpss, port=dport, dcmoid=dcmoid)
                if lsnme in dpg.keys():
                    virtwire = dpg[lsnme]
                    dls.update({lsnme: virtwire})
                i += 1
        elif ls[i] in vdls.keys():
            lsnme = ls[i]
            virtwire = vdls[lsnme]
            dls.update({lsnme: virtwire})
            i += 1
    for child in xml.findall('.//'):
        if child.find('portgroupName') != None:
            npg = child.find('portgroupName').text
            for i in range(0, lsno):
                if npg in dls.keys():
                    child.find('portgroupId').text = dls[npg]
    for child in xml.iter():
        for child1 in list(child):
            if child1.tag == 'sshLoginBannerText':
                child.remove(child1)
    vnics = xml.xpath('//vnics')
    vnicsb = (b''.join(map(etree.tostring, vnics))).strip().decode()
    clisetw = xml.xpath('//cliSettings')
    clisetwb = (b''.join(map(etree.tostring, clisetw))).strip().decode()
    clisetf = (clisetwb[:clisetwb.find("</cliSettings>")])
    edgepass = '<password>' + edgpass + '</password>'
    autoConfiguration = xml.xpath('//autoConfiguration')
    autoConfigurationb = (b''.join(map(etree.tostring, autoConfiguration))).strip().decode()
    print("##-- Generating XML to deploy the new edge gateway --##")
    xmlbody = xmlhead+'<edge>'+dmoid+nameb+tenantb+vseLogLevel+enableAesni+enableFips+'<appliances>'+appliancesizeb+'<appliance>'+apprsid+appdsid+apphid+appvid+'<cpuReservation>'+appcpub+'</cpuReservation>'+'<memoryReservation>'+appmemb+'</memoryReservation>'+'</appliance>'+'</appliances>'\
             +vnicsb+clisetf+edgepass+'</cliSettings>'+autoConfigurationb+'</edge>'
    crteurl = nsx_dbaseurl + edgeget
    print("##-- Edge gateway deployment in progress --##")
    crtereq = requests.post(crteurl, data=xmlbody, headers={'Content-Type': 'application/xml'}, auth=HTTPBasicAuth(destun, destpass))
    if crtereq.status_code == 201:
        print("##-- Edge gateway has been created --##")
        time.sleep(3)
        crtego(dcmoid)
    else:
        print("##-- Edge gateway deployment failed, Please check the settings by running the script again --##")

                        # Create grouping object for applications

def crtego(dcmoid):
    os.system('cls')
    print("##-- Creating custom Applications, Application Groups and other Grouping Objects on the new Edge--## ")
    dedgs = getdedges()
    getgourl = nsx_sbaseurl+application+'/scope/globalroot-0'
    getgo = requests.get(getgourl, headers={'Content-Type': 'application/*+xml;version=5.7'},auth=HTTPBasicAuth(sourceun, sourcepss))
    cont = getgo.content
    xml = etree.fromstring(cont)
    for child in xml.xpath('//objectId'):
        parent = child.getparent()
        parent.remove(child)
        for child1 in xml.xpath('//vsmUuid'):
            parent = child1.getparent()
            parent.remove(child1)
            for child2 in xml.xpath('//nodeId'):
                parent = child2.getparent()
                parent.remove(child2)
    for child in xml.iter():
        for child1 in list(child):
            for child2 in list(child1):
                if child2.find('id') != None and child2.find('id').text != 'globalroot-0':
                    edgname = child2.find('name').text
                    if edgname in dedgs.keys():
                        child2.find('id').text = dedgs[edgname]
    for app in xml.findall('.//application'):
        if app.find('scope/id') != None:
            id = app.find('scope/id').text
            appdata = (b''.join(map(etree.tostring, app))).strip().decode()
            xmlheader = '<?xml version="1.0" encoding="UTF-8"?>'
            xmlbody = xmlheader+'<application>'+appdata+'</application>'
            gourl = nsx_dbaseurl+application+'/'+id
            gocrte = requests.post(gourl, data=xmlbody, headers={'Content-Type': 'application/xml'}, auth=HTTPBasicAuth(destun, destpass))
    crtegoag(dcmoid)

                        #get applications from destination NSX

def getapps():
    apps = {}
    getdgourl = nsx_dbaseurl + application + '/scope/globalroot-0'
    getdgo = requests.get(getdgourl, headers={'Content-Type': 'application/*+xml;version=5.7'}, auth=HTTPBasicAuth(destun, destpass))
    cont1 = getdgo.content
    xml1 = etree.fromstring(cont1)
    for applist in xml1.findall('.//application'):
        if applist.find('objectId') != None:
            appid = applist.find('objectId').text
            appname = applist.find('name').text
            apps.update({appname:appid})
    return apps

                        # get applications from source NSX

def getsapps():
    apps = {}
    getgourl = nsx_sbaseurl + application + '/scope/globalroot-0'
    getdgo = requests.get(getgourl, headers={'Content-Type': 'application/*+xml;version=5.7'}, auth=HTTPBasicAuth(sourceun, sourcepss))
    cont1 = getdgo.content
    xml1 = etree.fromstring(cont1)
    for applist in xml1.findall('.//application'):
        if applist.find('objectId') != None:
            appid = applist.find('objectId').text
            appname = applist.find('name').text
            apps.update({appname:appid})
    return apps

                        # get application group from source NSX

def sapgrp():
    sappgrp = {}
    getgoagurl = nsx_sbaseurl + applicationgroup + '/scope/globalroot-0'
    getgo = requests.get(getgoagurl, headers={'Content-Type': 'application/*+xml;version=5.7'},
                         auth=HTTPBasicAuth(sourceun, sourcepss))
    cont = getgo.content
    xml = etree.fromstring(cont)
    for child in xml.xpath('//applicationGroup'):
        sappgrp.update({child.find('name').text:child.find('objectId').text})
    return sappgrp


                        # get application group from destination NSX

def dapgrp():
    dappgrp = {}
    getgodagurl = nsx_dbaseurl + applicationgroup + '/scope/globalroot-0'
    getgo = requests.get(getgodagurl, headers={'Content-Type': 'application/*+xml;version=5.7'},
                         auth=HTTPBasicAuth(destun, destpass))
    cont = getgo.content
    xml = etree.fromstring(cont)
    for child in xml.xpath('//applicationGroup'):
        dappgrp.update({child.find('name').text: child.find('objectId').text})

    return dappgrp

                        # create application groups

def crtegoag(dcmoid):
    apps = getapps()
    dedgs = getdedges()
    getgoagurl = nsx_sbaseurl + applicationgroup + '/scope/globalroot-0'
    getgodagurl = nsx_dbaseurl + applicationgroup + '/scope/globalroot-0'
    getgo = requests.get(getgoagurl, headers={'Content-Type': 'application/*+xml;version=5.7'},
                         auth=HTTPBasicAuth(sourceun, sourcepss))
    cont = getgo.content
    xml = etree.fromstring(cont)
    for child in xml.xpath('//applicationGroup/objectId'):
        parent = child.getparent()
        parent.remove(child)
        for child1 in xml.xpath('//vsmUuid'):
            parent = child1.getparent()
            parent.remove(child1)
            for child2 in xml.xpath('//nodeId'):
                parent = child2.getparent()
                parent.remove(child2)
    for child in xml.iter():                                       #change edgeID
        for child1 in list(child):
            for child2 in list(child1):
                if child2.find('id') != None and child2.find('id').text != 'globalroot-0':
                    edgname = child2.find('name').text
                    if edgname in dedgs.keys():
                        child2.find('id').text = dedgs[edgname]
    for app in xml.findall('.//applicationGroup'):
        if app.find('scope/id') != None:
            id = app.find('scope/id').text
            appdata = (b''.join(map(etree.tostring, app))).strip().decode()
            xmlheader = '<?xml version="1.0" encoding="UTF-8"?>'
            xmlbody = xmlheader + '<applicationGroup>' + appdata + '</applicationGroup>'
            gourl = nsx_dbaseurl + applicationgroup + '/' + id
            gocrte = requests.post(gourl, data=xmlbody, headers={'Content-Type': 'application/xml'}, auth=HTTPBasicAuth(destun, destpass))
            if gocrte.status_code == 201:
                agid = gocrte.content.decode()
                i = 0
                members = []
                for obj in app.findall('member'):
                    objname = obj.find('name').text
                    if objname in apps.keys():
                        obj.find('objectId').text = apps[objname]
                        members.append(obj.find('objectId').text)
                memlen = len(members)
                for i in range(0,memlen):
                    memurl = nsx_dbaseurl + applicationgroup + '/' + agid + '/members/'+ members[i]
                    requests.put(memurl, headers={'Content-Type': 'application/xml'}, auth=HTTPBasicAuth(destun, destpass))
                    i += 1
                members.clear()
    ipsets(dcmoid)

                        # create IPsets

def ipsets(dcmoid):
    os.system('cls')
    print("##-- Creating IPsets on the new Edge --#")
    dedgs = getdedges()
    ipurl = nsx_sbaseurl+ipset+'/scope/globalroot-0'
    ipreq = requests.get(ipurl, headers = {'Content-Type': 'application/*+xml;version=5.7'}, auth=HTTPBasicAuth(sourceun, sourcepss))
    cont = ipreq.content
    xml = etree.fromstring(cont)
    for child in xml.xpath('//objectId'):
        parent = child.getparent()
        parent.remove(child)
        for child1 in xml.xpath('//vsmUuid'):
            parent = child1.getparent()
            parent.remove(child1)
            for child2 in xml.xpath('//nodeId'):
                parent = child2.getparent()
                parent.remove(child2)
    for child in xml.iter():
        for child1 in list(child):
            for child2 in list(child1):
                if child2.find('id') != None and child2.find('id').text != 'globalroot-0':
                    edgname = child2.find('name').text
                    if edgname in dedgs.keys():
                        child2.find('id').text = dedgs[edgname]
    for app in xml.findall('.//ipset'):
        if app.find('scope/id') != None:
            id = app.find('scope/id').text
            appdata = (b''.join(map(etree.tostring, app))).strip().decode()
            xmlheader = '<?xml version="1.0" encoding="UTF-8"?>'
            xmlbody = xmlheader+'<ipset>'+appdata+'</ipset>'
            ipdurl = nsx_dbaseurl+ipset+'/'+id
            ipdcrte = requests.post(ipdurl, data=xmlbody, headers={'Content-Type': 'application/xml'}, auth=HTTPBasicAuth(destun, destpass))
    edgfirewall(dcmoid)

                        # publish firewall rules

def edgfirewall(dcmoid):
    appsobjs = []
    rulchk = []
    perffwl = []
    os.system('cls')
    print("##-- Publishing Firewall rules on the new edge --##")
    xmlheader = '<?xml version="1.0" encoding="UTF-8"?>'
    sapps = getsapps()
    dapps = getapps()
    sagrp = sapgrp()
    dagrp = dapgrp()
    ddc = moid(viewType=[vim.Datacenter], host=destvc, user=destvcun, pwd=destvcpss, port=dport, dcmoid=None)
    sdc = smoid(viewType=[vim.Datacenter], host=sourcevc, user=sourcevcun, pwd=sourcevcpss, port=sport)
    drp = moid(viewType=[vim.ResourcePool], host=destvc, user=destvcun, pwd=destvcpss, port=dport, dcmoid=dcmoid)
    srp = smoid(viewType=[vim.ResourcePool], host=sourcevc, user=sourcevcun, pwd=sourcevcpss, port=sport)
    dds = moid(viewType=[vim.Datastore], host=destvc, user=destvcun, pwd=destvcpss, port=dport, dcmoid=dcmoid)
    sds = smoid(viewType=[vim.Datastore], host=sourcevc, user=sourcevcun, pwd=sourcevcpss, port=sport)
    dhs = moid(viewType=[vim.HostSystem], host=destvc, user=destvcun, pwd=destvcpss, port=dport, dcmoid=dcmoid)
    shs = smoid(viewType=[vim.HostSystem], host=sourcevc, user=sourcevcun, pwd=sourcevcpss, port=sport)
    dcl = moid(viewType=[vim.ComputeResource], host=destvc, user=destvcun, pwd=destvcpss, port=dport, dcmoid=dcmoid)
    scl = smoid(viewType=[vim.ComputeResource], host=sourcevc, user=sourcevcun, pwd=sourcevcpss, port=sport)
    dvm = moid(viewType=[vim.VirtualMachine], host=destvc, user=destvcun, pwd=destvcpss, port=dport, dcmoid=dcmoid)
    svm = smoid(viewType=[vim.VirtualMachine], host=sourcevc, user=sourcevcun, pwd=sourcevcpss, port=sport)
    dnw = moid(viewType=[vim.Network], host=destvc, user=destvcun, pwd=destvcpss, port=dport, dcmoid=dcmoid)
    snw = smoid(viewType=[vim.Network], host=sourcevc, user=sourcevcun, pwd=sourcevcpss, port=sport)
    dls = getdls()
    sls = getsls()
    sedg = getedges()
    dedg = getdedges()
    if edgeid in sedg.values():
        sedg = list(sedg.keys())[list(sedg.values()).index(edgeid)]
        edgeid1 = dedg[sedg]
    fwurl = nsx_sbaseurl+edgeget+'/'+edgeid+fwconfig
    fwdurl = nsx_dbaseurl + edgeget + '/' + edgeid1 + fwconfig+'/rules'
    fwdgeturl = nsx_dbaseurl + edgeget + '/' + edgeid1 + fwconfig
    fwreq = requests.get(fwurl, headers = {'Content-Type': 'application/*+xml;version=5.7'}, auth=HTTPBasicAuth(sourceun, sourcepss))
    cont = fwreq.content
    xml = etree.fromstring(cont)
    fwenable = xml.xpath('//firewall/enabled')
    fwgcfig = xml.xpath('//globalConfig')
    fwdpcfig = xml.xpath('//defaultPolicy')
    fwenableb = (b''.join(map(etree.tostring, fwenable))).strip().decode()
    fwgcfigb = (b''.join(map(etree.tostring, fwgcfig))).strip().decode()
    fwdpcfigb = (b''.join(map(etree.tostring, fwdpcfig))).strip().decode()
    xmlcfgbdy = xmlheader+'<firewall>'+fwenableb+fwgcfigb+fwdpcfigb+'</firewall>'
    fwdcfgreq = requests.put(fwdgeturl, data=xmlcfgbdy, headers={'Content-Type': 'application/xml;version=5.7'},
                           auth=HTTPBasicAuth(destun, destpass))
    for child in xml.xpath('//id'):
        parent = child.getparent()
        parent.remove(child)
        for child1 in xml.xpath('//ruleTag'):
            parent = child1.getparent()
            parent.remove(child1)
            for child2 in xml.xpath('//version'):
                parent = child2.getparent()
                parent.remove(child2)
    for firewll in xml.findall('.//applicationId'):
        if firewll.text in sapps.values():
            appname = list(sapps.keys())[list(sapps.values()).index(firewll.text)]
            try:
                firewll.text = dapps[appname]
            except KeyError:
                appsobjs.append(appname+'-Service')
        elif firewll.text in sagrp.values():
            appname = list(sagrp.keys())[list(sagrp.values()).index(firewll.text)]
            try:
                firewll.text = dagrp[appname]
            except KeyError:
                appsobjs.append(appname+'-ServiceGroup')
    for goid in xml.findall('.//groupingObjectId'):
        if goid.text in sdc.values():
            goname = list(sdc.keys())[list(sdc.values()).index(goid.text)]
            try:
                goid.text = ddc[goname]
            except KeyError:
                appsobjs.append(goname+'-Datacenter')
        elif goid.text in srp.values():
            goname = list(srp.keys())[list(srp.values()).index(goid.text)]
            try:
                goid.text = drp[goname]
            except KeyError:
                appsobjs.append(goname+'-Resourcepool')
        elif goid.text in sds.values():
            goname = list(sds.keys())[list(sds.values()).index(goid.text)]
            try:
                goid.text = dds[goname]
            except KeyError:
                appsobjs.append(goname+'-Datastore')
        elif goid.text in shs.values():
            goname = list(shs.keys())[list(shs.values()).index(goid.text)]
            try:
                goid.text = dhs[goname]
            except KeyError:
                appsobjs.append(goname+'-HostSystem')
        elif goid.text in scl.values():
            goname = list(scl.keys())[list(scl.values()).index(goid.text)]
            try:
                goid.text = dcl[goname]
            except KeyError:
                appsobjs.append(goname+'-Cluster')
        elif goid.text in svm.values():
            goname = list(svm.keys())[list(svm.values()).index(goid.text)]
            try:
                goid.text = dvm[goname]
            except KeyError:
                appsobjs.append(goname+'-VirtualMachine')
        elif goid.text in snw.values():
            goname = list(snw.keys())[list(snw.values()).index(goid.text)]
            try:
                goid.text = dnw[goname]
            except KeyError:
                appsobjs.append(goname+'-Portgroup')
        elif goid.text in sls.values():
            goname = list(sls.keys())[list(sls.values()).index(goid.text)]
            try:
                goid.text = dls[goname]
            except KeyError:
                appsobjs.append(goname+'-LogicalSwitch')
    for rul in xml.findall('.//firewallRule'):
        rtype = rul.find('ruleType').text
        if rtype == 'user':
            fwbody = etree.tostring(rul).decode()
            xmlbody = xmlheader+'<firewallRules>'+fwbody+'</firewallRules>'
            fwdreq = requests.post(fwdurl, data=xmlbody, headers={'Content-Type': 'application/xml;version=5.7'}, auth=HTTPBasicAuth(destun, destpass))
            fwget = requests.get(fwdgeturl, headers = {'Content-Type': 'application/*+xml;version=5.7'},auth=HTTPBasicAuth(destun, destpass))
            fwcont = fwget.content
            xml3 = etree.fromstring(fwcont)
            for child5 in xml3.findall('.//ruleTag'):
                perffwl.append(child5.text)
            if fwdreq.status_code == 400:
                for firewll in rul.findall('.//applicationId'):
                    if firewll.text in dapps.values():
                        pass
                    elif firewll.text in sagrp.values():
                        pass
                    else:
                        parent = firewll.getparent()
                        parent.remove(firewll)
                for goid in rul.findall('.//groupingObjectId'):
                    if goid.text in ddc.values():
                        pass
                    elif goid.text in drp.values():
                        pass
                    elif goid.text in dds.values():
                        pass
                    elif goid.text in dhs.values():
                        pass
                    elif goid.text in dcl.values():
                        pass
                    elif goid.text in dvm.values():
                        pass
                    elif goid.text in dnw.values():
                        pass
                    elif goid.text in dls.values():
                        pass
                    else:
                        parent = goid.getparent()
                        parent.remove(goid)
                fwbody = etree.tostring(rul).decode()
                xmlbody = xmlheader + '<firewallRules>' + fwbody + '</firewallRules>'
                fwdreq = requests.post(fwdurl, data=xmlbody, headers={'Content-Type': 'application/xml;version=5.7'},
                                       auth=HTTPBasicAuth(destun, destpass))
            fwget = requests.get(fwdgeturl, headers={'Content-Type': 'application/*+xml;version=5.7'},
                                 auth=HTTPBasicAuth(destun, destpass))
            fwcont = fwget.content
            xml3 = etree.fromstring(fwcont)
            for child6 in xml3.findall('.//ruleTag'):
                if child6.text not in perffwl:
                    rulchk.append(child6.text)
    edgnat(dcmoid,appsobjs,rulchk)

                        # publish NAT rules

def edgnat(dcmoid,appsobjs,rulchk):
    os.system('cls')
    print("##-- Publishing NAT rules on the new edge --#")
    sedg = getedges()
    dedg = getdedges()
    if edgeid in sedg.values():
        sedg = list(sedg.keys())[list(sedg.values()).index(edgeid)]
        edgeid1 = dedg[sedg]
    naturl = nsx_sbaseurl+edgeget+'/'+edgeid+natconfig
    natreq = requests.get(naturl, headers = {'Content-Type': 'application/*+xml;version=5.7'}, auth=HTTPBasicAuth(sourceun, sourcepss ))
    cont = natreq.content
    xml = etree.fromstring(cont)
    for child in xml.xpath('//ruleId'):
        parent = child.getparent()
        parent.remove(child)
        for child1 in xml.xpath('//ruleTag'):
            parent = child1.getparent()
            parent.remove(child1)
    xmlheader = '<?xml version="1.0" encoding="UTF-8"?>'
    natrules = xml.xpath('//natRules')
    natbody = (b''.join(map(etree.tostring, natrules))).strip().decode()
    xmlbody = xmlheader+natbody
    naturl = nsx_dbaseurl + edgeget + '/' + edgeid1 + natconfigrules
    natreq = requests.post(naturl, data=xmlbody, headers={'Content-Type': 'application/xml;version=5.7'}, auth=HTTPBasicAuth(destun, destpass))
    edgdhcp(dcmoid,appsobjs,rulchk)

                        # create dhcp pools and relays

def edgdhcp(dcmoid,appsobjs,rulchk):
    os.system('cls')
    print("##-- Publishing DHCP Pools/Relay settings on the new edge --#")
    xmlheader = '<?xml version="1.0" encoding="UTF-8"?>'
    sips = getsipsets()
    dips = getdipsets()
    sedg = getedges()
    dedg = getdedges()
    if edgeid in sedg.values():
        sedg = list(sedg.keys())[list(sedg.values()).index(edgeid)]
        edgeid1 = dedg[sedg]
    dhcpurl = nsx_sbaseurl+edgeget+'/'+edgeid+dhcpconfig
    dhcpreq = requests.get(dhcpurl, headers = {'Content-Type': 'application/*+xml;version=5.7'}, auth=HTTPBasicAuth(sourceun, sourcepss))
    cont = dhcpreq.content
    xml = etree.fromstring(cont)
    ippool = xml.xpath('//ipPool')
    for child in ippool:
        ippoolbody = (b''.join(map(etree.tostring, child))).strip().decode()
        ipbody = xmlheader + '<ipPool>'+ippoolbody +'</ipPool>'
        ipoolurl = nsx_dbaseurl + edgeget + '/' + edgeid1 + dhcppool
        dpool = requests.post(ipoolurl, data=ipbody,
                              headers={'Content-Type': 'application/xml;version=5.7'},
                              auth=HTTPBasicAuth(destun, destpass))
    for child in xml.findall('.//groupingObjectId'):
        if child.text in sips.values():
            appname = list(sips.keys())[list(sips.values()).index(child.text)]
            child.text = dips[appname]
    relay = xml.xpath('//relay')
    relaybody = (b''.join(map(etree.tostring, relay))).strip().decode()
    relayurl = nsx_dbaseurl+edgeget+'/'+edgeid1+dhcprelay
    drelay = requests.put(relayurl, data=xmlheader+relaybody, headers={'Content-Type': 'application/xml;version=5.7'}, auth=HTTPBasicAuth(destun, destpass))
    edgipsec(dcmoid,appsobjs,rulchk)

                        # create ipsec sites

def edgipsec(dcmoid,appsobjs,rulchk):
    os.system('cls')
    print("##-- Publishing IPsec site settings on the new edge --#")
    sedg = getedges()
    dedg = getdedges()
    if edgeid in sedg.values():
        sedg = list(sedg.keys())[list(sedg.values()).index(edgeid)]
        edgeid1 = dedg[sedg]
    ipsecurl = nsx_sbaseurl+edgeget+'/'+edgeid+ipsec+'?showSensitiveData=true'
    ipsecreq = requests.get(ipsecurl, headers = {'Content-Type': 'application/*+xml;version=5.7'}, auth=HTTPBasicAuth(sourceun, sourcepss))
    cont = ipsecreq.content
    xml = etree.fromstring(cont)
    xml.find('enabled').text = 'false'
    for child in xml.xpath('//siteId'):
        parent = child.getparent()
        parent.remove(child)
        for child1 in xml.xpath('//version'):
            parent = child1.getparent()
            parent.remove(child1)
    xmlheader = '<?xml version="1.0" encoding="UTF-8"?>'
    ipsecbdy = xml.xpath('//ipsec')
    ipsecbody = (b''.join(map(etree.tostring, ipsecbdy))).strip().decode()
    xmlbody = xmlheader + ipsecbody
    ipsecpsturl = nsx_dbaseurl+edgeget+'/'+edgeid1+ipsec
    requests.put(ipsecpsturl, data= xmlbody, headers={'Content-Type': 'application/xml;version=5.7'}, auth=HTTPBasicAuth(destun, destpass))
    os.system('cls')
    print("Edge gateway is ready for use")
    print("The following vSphere Objects are not avaiable at the destination environment")
    print("")
    print("vSphere Objects:", appsobjs)
    print("")
    print("The following rules needs to be validated manually by the end user as the associated vSphere objects are not available at the destination environment ")
    print("")
    print("Rules that require manual validation:",rulchk)

def ssgroup():
    apps = {}
    sgurl = nsx_sbaseurl + sg + 'globalroot-0'
    sgreq = requests.get(sgurl, headers={'Content-Type': 'application/*+xml;version=5.7'},
                         auth=HTTPBasicAuth(sourceun, sourcepss))
    cont = sgreq.content
    xml = etree.fromstring(cont)
    for applist in xml.findall('.//securitygroup'):
        if applist.find('objectId') != None:
            appid = applist.find('objectId').text
            appname = applist.find('name').text
            apps.update({appname: appid})
    return apps

def dsgroup():
    apps = {}
    sgurl = nsx_dbaseurl + sg + 'globalroot-0'
    sgreq = requests.get(sgurl, headers={'Content-Type': 'application/*+xml;version=5.7'},
                         auth=HTTPBasicAuth(destun, destpass))
    cont = sgreq.content
    xml = etree.fromstring(cont)
    for applist in xml.findall('.//securitygroup'):
        if applist.find('objectId') != None:
            appid = applist.find('objectId').text
            appname = applist.find('name').text
            apps.update({appname: appid})
    return apps

def scspolicy():
    scp={}
    scsurl = nsx_sbaseurl + scpl + '/all?startIndex=0&pageSize=1024'
    screq = requests.get(scsurl, headers={'Content-Type': 'application/*+xml;version=5.7'},
                         auth=HTTPBasicAuth(sourceun, sourcepss))
    cont = screq.content
    xml = etree.fromstring(cont)
    for sgrp in xml.iter('securityPolicy'):
        if sgrp.find('objectId') != None:
            sgid = sgrp.find('objectId').text
            sgname = sgrp.find('name').text
            scp.update({sgname:sgid})
    return scp

def scdpolicy():
    scp={}
    scsurl = nsx_dbaseurl + scpl + '/all?startIndex=0&pageSize=1024'
    screq = requests.get(scsurl, headers={'Content-Type': 'application/*+xml;version=5.7'},
                         auth=HTTPBasicAuth(destun, destpass))
    cont = screq.content
    xml = etree.fromstring(cont)
    for sgrp in xml.iter('securityPolicy'):
        if sgrp.find('objectId') != None:
            sgid = sgrp.find('objectId').text
            sgname = sgrp.find('name').text
            scp.update({sgname:sgid})
    return scp

def dfw():
    os.system('cls')
    print("##-- Gathering distributed firewall data and vSphere Objects from source --##")
    xmlheader = '<?xml version="1.0" encoding="UTF-8"?>'
    appobjs = []
    rulchk = []
    sapps = getsapps()
    dapps = getapps()
    sagrp = sapgrp()
    dagrp = dapgrp()
    srcgrp = ssgroup()
    desgrp = dsgroup()
    ddc = smoid(viewType=[vim.Datacenter], host=destvc, user=destvcun, pwd=destvcpss, port=dport)
    sdc = smoid(viewType=[vim.Datacenter], host=sourcevc, user=sourcevcun, pwd=sourcevcpss, port=sport)
    drp = smoid(viewType=[vim.ResourcePool], host=destvc, user=destvcun, pwd=destvcpss, port=dport)
    srp = smoid(viewType=[vim.ResourcePool], host=sourcevc, user=sourcevcun, pwd=sourcevcpss, port=sport)
    dds = smoid(viewType=[vim.Datastore], host=destvc, user=destvcun, pwd=destvcpss, port=dport)
    sds = smoid(viewType=[vim.Datastore], host=sourcevc, user=sourcevcun, pwd=sourcevcpss, port=sport)
    dhs = smoid(viewType=[vim.HostSystem], host=destvc, user=destvcun, pwd=destvcpss, port=dport)
    shs = smoid(viewType=[vim.HostSystem], host=sourcevc, user=sourcevcun, pwd=sourcevcpss, port=sport)
    dcl = smoid(viewType=[vim.ComputeResource], host=destvc, user=destvcun, pwd=destvcpss, port=dport)
    scl = smoid(viewType=[vim.ComputeResource], host=sourcevc, user=sourcevcun, pwd=sourcevcpss, port=sport)
    dvm = smoid(viewType=[vim.VirtualMachine], host=destvc, user=destvcun, pwd=destvcpss, port=dport)
    svm = smoid(viewType=[vim.VirtualMachine], host=sourcevc, user=sourcevcun, pwd=sourcevcpss, port=sport)
    dnw = smoid(viewType=[vim.Network], host=destvc, user=destvcun, pwd=destvcpss, port=dport)
    snw = smoid(viewType=[vim.Network], host=sourcevc, user=sourcevcun, pwd=sourcevcpss, port=sport)
    siuid = vmid(viewType=[vim.VirtualMachine], host=sourcevc, user=sourcevcun, pwd=sourcevcpss, port=sport)
    diuid = vmid(viewType=[vim.VirtualMachine], host=destvc, user=destvcun, pwd=destvcpss, port=dport)
    dls = getdls()
    sls = getsls()
    sedg = getedges()
    dedg = getdedges()
    sips = getsipsets()
    dips = getdipsets()
    xptcfigurl = nsx_sbaseurl+dfwconfig
    iptcfigurl = nsx_dbaseurl+dfwl3
    ipl3rsurl = nsx_dbaseurl+dfwl3rs
    ipl2url = nsx_dbaseurl+dfwl2
    xptcfgreq = requests.get(xptcfigurl, headers={'Content-Type': 'application/*+xml;version=5.7'}, auth=HTTPBasicAuth(sourceun, sourcepss))
    cont = xptcfgreq.content
    xml = etree.fromstring(cont)
    print("##-- Modifying the existing configuration to suit the destination environment --##")
    for goid in xml.findall('.//appliedTo'):
        value = goid.find('value').text
        if value in sdc.values():
            goname = list(sdc.keys())[list(sdc.values()).index(value)]
            try:
                goid.find('value').text = ddc[goname]
            except KeyError:
                appobjs.append(goname+'-datacenter')
        elif value in srp.values():
            goname = list(srp.keys())[list(srp.values()).index(value)]
            try:
                goid.find('value').text = drp[goname]
            except KeyError:
                appobjs.append(goname+'-ResourcePool')
        elif value in sds.values():
            goname = list(sds.keys())[list(sds.values()).index(value)]
            try:
                goid.find('value').text = dds[goname]
            except KeyError:
                appobjs.append(goname+'-Datastore')
        elif value in shs.values():
            goname = list(shs.keys())[list(shs.values()).index(value)]
            try:
                goid.find('value').text = dhs[goname]
            except KeyError:
                appobjs.append(goname+'-HostSystem')
        elif value in scl.values():
            goname = list(scl.keys())[list(scl.values()).index(value)]
            try:
                goid.find('value').text = dcl[goname]
            except KeyError:
                appobjs.append(goname+'-Cluster')
        elif value in svm.values():
            goname = list(svm.keys())[list(svm.values()).index(value)]
            try:
                goid.find('value').text = dvm[goname]
            except KeyError:
                appobjs.append(goname+'-VirtualMachine')
        elif value in snw.values():
            goname = list(snw.keys())[list(snw.values()).index(value)]
            try:
                goid.find('value').text = dnw[goname]
            except KeyError:
                appobjs.append(goname+'-Portgroup')
        elif value in sls.values():
            goname = list(sls.keys())[list(sls.values()).index(value)]
            try:
                goid.find('value').text = dls[goname]
            except KeyError:
                appobjs.append(goname+'-LogicalSwitch')
        elif value in sapps.values():
            appname = list(sapps.keys())[list(sapps.values()).index(value)]
            try:
                goid.find('value').text = dapps[appname]
            except KeyError:
                appobjs.append(goname+'-Service')
        elif value in sagrp.values():
            appname = list(sagrp.keys())[list(sagrp.values()).index(value)]
            try:
                goid.find('value').text = dagrp[appname]
            except KeyError:
                appobjs.append(goname+'-ServiceGroup')
        elif value in sedg.values():
            appname = list(sedg.keys())[list(sedg.values()).index(value)]
            try:
                goid.find('value').text = dedg[appname]
            except KeyError:
                appobjs.append(goname+'-edgeGateway')
        elif value in sips.values():
            goname = list(sips.keys())[list(sips.values()).index(value)]
            try:
                goid.find('value').text = dips[goname]
            except KeyError:
                appobjs.append(goname+'-IPsets')
        elif value in srcgrp.values():
            goname = list(srcgrp.keys())[list(srcgrp.values()).index(value)]
            try:
                goid.find('value').text = desgrp[goname]
            except KeyError:
                appobjs.append(goname+'-SecurityGroup')
        elif value[:value.find('.')] in siuid.values():
            goname = list(siuid.keys())[list(siuid.values()).index(value[:value.find('.')])]
            uidsuffix = value[value.find('.'):]
            try:
                duid = diuid[goname]
                vnicid = duid+uidsuffix
                goid.find('value').text = vnicid
            except KeyError:
                appobjs.append(goname+'-vNIC Adapter')
    for goid in xml.findall('.//source'):
        value = goid.find('value').text
        if value in sdc.values():
            goname = list(sdc.keys())[list(sdc.values()).index(value)]
            try:
                goid.find('value').text = ddc[goname]
            except KeyError:
                appobjs.append(goname+'-Datacenter')
        elif value in srp.values():
            goname = list(srp.keys())[list(srp.values()).index(value)]
            try:
                goid.find('value').text = drp[goname]
            except KeyError:
                appobjs.append(goname+'-ResourcePool')
        elif value in sds.values():
            goname = list(sds.keys())[list(sds.values()).index(value)]
            try:
                goid.find('value').text = dds[goname]
            except KeyError:
                appobjs.append(goname+'-Datastore')
        elif value in shs.values():
            goname = list(shs.keys())[list(shs.values()).index(value)]
            try:
                goid.find('value').text = dhs[goname]
            except KeyError:
                appobjs.append(goname+'-HostSystem')
        elif value in scl.values():
            goname = list(scl.keys())[list(scl.values()).index(value)]
            try:
                goid.find('value').text = dcl[goname]
            except KeyError:
                appobjs.append(goname+'-Cluster')
        elif value in svm.values():
            goname = list(svm.keys())[list(svm.values()).index(value)]
            try:
                goid.find('value').text = dvm[goname]
            except KeyError:
                appobjs.append(goname+'-VirtualMachine')
        elif value in snw.values():
            goname = list(snw.keys())[list(snw.values()).index(value)]
            try:
                goid.find('value').text = dnw[goname]
            except KeyError:
                appobjs.append(goname+'-Portgroup')
        elif value in sls.values():
            goname = list(sls.keys())[list(sls.values()).index(value)]
            try:
                goid.find('value').text = dls[goname]
            except KeyError:
                appobjs.append(goname+'-LogicalSwitch')
        elif value in sapps.values():
            appname = list(sapps.keys())[list(sapps.values()).index(value)]
            try:
                goid.find('value').text = dapps[appname]
            except KeyError:
                appobjs.append(goname+'-Service')
        elif value in sagrp.values():
            appname = list(sagrp.keys())[list(sagrp.values()).index(value)]
            try:
                goid.find('value').text = dagrp[appname]
            except KeyError:
                appobjs.append(goname+'-ServiceGroup')
        elif value in sedg.values():
            appname = list(sedg.keys())[list(sedg.values()).index(value)]
            try:
                goid.find('value').text = dedg[appname]
            except KeyError:
                appobjs.append(goname+'-edgeGateway')
        elif value in sips.values():
            goname = list(sips.keys())[list(sips.values()).index(value)]
            try:
                goid.find('value').text = dips[goname]
            except KeyError:
                appobjs.append(goname+'-IPset')
        elif value[:value.find('.')] in siuid.values():
            goname = list(siuid.keys())[list(siuid.values()).index(value[:value.find('.')])]
            uidsuffix = value[value.find('.'):]
            try:
                duid = diuid[goname]
                vnicid = duid + uidsuffix
                goid.find('value').text = vnicid
            except KeyError:
                appobjs.append(goname+'-vNIC Adapter')
        elif value in srcgrp.values():
            goname = list(srcgrp.keys())[list(srcgrp.values()).index(value)]
            try:
                goid.find('value').text = desgrp[goname]
            except KeyError:
                appobjs.append(goname+'-SecurityGroup')
    for goid in xml.findall('.//destination'):
        value = goid.find('value').text
        if value in sdc.values():
            goname = list(sdc.keys())[list(sdc.values()).index(value)]
            try:
                goid.find('value').text = ddc[goname]
            except KeyError:
                appobjs.append(goname+'-Datacenter')
        elif value in srp.values():
            goname = list(srp.keys())[list(srp.values()).index(value)]
            try:
                goid.find('value').text = drp[goname]
            except KeyError:
                appobjs.append(goname+'-ResourcePool')
        elif value in sds.values():
            goname = list(sds.keys())[list(sds.values()).index(value)]
            try:
                goid.find('value').text = dds[goname]
            except KeyError:
                appobjs.append(goname+'-Datastore')
        elif value in shs.values():
            goname = list(shs.keys())[list(shs.values()).index(value)]
            try:
                goid.find('value').text = dhs[goname]
            except KeyError:
                appobjs.append(goname+'-HostSystem')
        elif value in scl.values():
            goname = list(scl.keys())[list(scl.values()).index(value)]
            try:
                goid.find('value').text = dcl[goname]
            except KeyError:
                appobjs.append(goname+'-Cluster')
        elif value in svm.values():
            goname = list(svm.keys())[list(svm.values()).index(value)]
            try:
                goid.find('value').text = dvm[goname]
            except KeyError:
                appobjs.append(goname+'-VirtualMachine')
        elif value in snw.values():
            goname = list(snw.keys())[list(snw.values()).index(value)]
            try:
                goid.find('value').text = dnw[goname]
            except KeyError:
                appobjs.append(goname+'-Portgroup')
        elif value in sls.values():
            goname = list(sls.keys())[list(sls.values()).index(value)]
            try:
                goid.find('value').text = dls[goname]
            except KeyError:
                appobjs.append(goname+'-LogicalSwitch')
        elif value in sapps.values():
            appname = list(sapps.keys())[list(sapps.values()).index(value)]
            try:
                goid.find('value').text = dapps[appname]
            except KeyError:
                appobjs.append(goname+'-Service')
        elif value in sagrp.values():
            appname = list(sagrp.keys())[list(sagrp.values()).index(value)]
            try:
                goid.find('value').text = dagrp[appname]
            except KeyError:
                appobjs.append(goname+'-Servicegroup')
        elif value in sedg.values():
            appname = list(sedg.keys())[list(sedg.values()).index(value)]
            try:
                goid.find('value').text = dedg[appname]
            except KeyError:
                appobjs.append(goname+'-edgeGateway')
        elif value in sips.values():
            goname = list(sips.keys())[list(sips.values()).index(value)]
            try:
                goid.find('value').text = dips[goname]
            except KeyError:
                appobjs.append(goname+'-IPset')
        elif value[:value.find('.')] in siuid.values():
            goname = list(siuid.keys())[list(siuid.values()).index(value[:value.find('.')])]
            uidsuffix = value[value.find('.'):]
            try:
                duid = diuid[goname]
                vnicid = duid + uidsuffix
                goid.find('value').text = vnicid
            except KeyError:
                appobjs.append(goname+'-vNIC Adapter')
        elif value in srcgrp.values():
            goname = list(srcgrp.keys())[list(srcgrp.values()).index(value)]
            try:
                goid.find('value').text = desgrp[goname]
            except KeyError:
                appobjs.append(goname+'-SecurityGroup')
    for goid in xml.findall('.//service'):
        aid = goid.find('value').text
        if aid in sapps.values():
            appname = list(sapps.keys())[list(sapps.values()).index(aid)]
            try:
                goid.find('value').text = dapps[appname]
            except KeyError:
                appobjs.append(appname+'-Service')
        if aid in sagrp.values():
            appname = list(sagrp.keys())[list(sagrp.values()).index(aid)]
            try:
                goid.find('value').text = dagrp[appname]
            except KeyError:
                appobjs.append(appname+'-ServiceGroup')
    for tstmp in xml.findall('.//section'):
        del tstmp.attrib["id"]
        del tstmp.attrib["generationNumber"]
        del tstmp.attrib["timestamp"]
    for tstmp in xml.findall('.'):
        del tstmp.attrib["timestamp"]
    for child in xml.xpath('//generationNumber'):
        parent = child.getparent()
        parent.remove(child)
        for child1 in xml.xpath('//sectionId'):
            parent = child1.getparent()
            parent.remove(child1)
    for tstmp in xml.findall('.//rule'):
        del tstmp.attrib["id"]
    print("##-- Creating sections and rules in the destination enironment --##")
    for fwlcfg in xml.findall('.//section'):
        fwlsec = fwlcfg
        try:
            fwlsec.attrib["managedBy"]
        except KeyError:
            rule = []
            if fwlsec.attrib["type"] == 'LAYER3':
                for child8 in fwlsec.iter('section'):
                    for child9 in child8.findall('rule'):
                        rule.append(etree.tostring(child9))
                        parent = child9.getparent()
                        parent.remove(child9)
                    fwlbdy = etree.tostring(fwlsec).decode()
                    l3req = requests.post(iptcfigurl, data=xmlheader + fwlbdy,
                                          headers={'Content-Type': 'application/xml;version=5.7'},
                                          auth=HTTPBasicAuth(destun, destpass))
                    if l3req.status_code == 201:
                        secont = l3req.content
                        etg = l3req.headers['ETag']
                        secxml = etree.fromstring(secont)
                        for fwlrulcfg in secxml.iter('section'):
                            secid = fwlrulcfg.attrib["id"]
                            i = 0
                            rulurl = nsx_dbaseurl + dfwl3 + '/' + secid + '/rules'
                            if len(rule) > 0:
                                for i in range(0, len(rule)):
                                    xmlbody3 = xmlheader + rule[i].decode()
                                    l3rulreq = requests.post(rulurl, data=xmlbody3, headers={'Content-Type': 'application/xml;version=5.7', 'If-Match': etg}, auth=HTTPBasicAuth(destun, destpass))
                                    if l3rulreq.status_code == 201:
                                        etg = l3rulreq.headers['ETag']
                                        i += 1
                                    elif l3rulreq.status_code == 404:
                                        rulxml = etree.fromstring(rule[i])
                                        for goid in rulxml.findall('.//appliedTo'):
                                            value = goid.find('value').text
                                            if value in ddc.values():
                                                pass
                                            elif value in drp.values():
                                                pass
                                            elif value in dds.values():
                                                pass
                                            elif value in dhs.values():
                                                pass
                                            elif value in dcl.values():
                                                pass
                                            elif value in dvm.values():
                                                pass
                                            elif value in dnw.values():
                                                pass
                                            elif value in dls.values():
                                                pass
                                            elif value in dapps.values():
                                                pass
                                            elif value in dagrp.values():
                                                pass
                                            elif value in dedg.values():
                                                pass
                                            elif value in dips.values():
                                                pass
                                            elif value in desgrp.values():
                                                pass
                                            elif value[:value.find('.')] in diuid.values():
                                                pass
                                            else:
                                                parent = goid.getparent()
                                                parent.remove(goid)
                                        for goid in rulxml.findall('.//source'):
                                            value = goid.find('value').text
                                            if value in ddc.values():
                                                pass
                                            elif value in drp.values():
                                                pass
                                            elif value in dds.values():
                                                pass
                                            elif value in dhs.values():
                                                pass
                                            elif value in dcl.values():
                                                pass
                                            elif value in dvm.values():
                                                pass
                                            elif value in dnw.values():
                                                pass
                                            elif value in dls.values():
                                                pass
                                            elif value in dapps.values():
                                                pass
                                            elif value in dagrp.values():
                                                pass
                                            elif value in dedg.values():
                                                pass
                                            elif value in dips.values():
                                                pass
                                            elif value in desgrp.values():
                                                pass
                                            elif value[:value.find('.')] in diuid.values():
                                                pass
                                            else:
                                                parent = goid.getparent()
                                                parent.remove(goid)
                                        for goid in rulxml.findall('.//destination'):
                                            value = goid.find('value').text
                                            if value in ddc.values():
                                                pass
                                            elif value in drp.values():
                                                pass
                                            elif value in dds.values():
                                                pass
                                            elif value in dhs.values():
                                                pass
                                            elif value in dcl.values():
                                                pass
                                            elif value in dvm.values():
                                                pass
                                            elif value in dnw.values():
                                                pass
                                            elif value in dls.values():
                                                pass
                                            elif value in dapps.values():
                                                pass
                                            elif value in dagrp.values():
                                                pass
                                            elif value in dedg.values():
                                                pass
                                            elif value in dips.values():
                                                pass
                                            elif value in desgrp.values():
                                                pass
                                            elif value[:value.find('.')] in diuid.values():
                                                pass
                                            else:
                                                parent = goid.getparent()
                                                parent.remove(goid)
                                        for goid in rulxml.findall('.//service'):
                                            aid = goid.find('value').text
                                            if aid in dapps.values():
                                                pass
                                            elif aid in dagrp.values():
                                                pass
                                            else:
                                                parent = goid.getparent()
                                                parent.remove(goid)
                                        rulexml = etree.tostring(rulxml)
                                        xmlbody3 = xmlheader + rulexml.decode()
                                        l3rulreq = requests.post(rulurl, data=xmlbody3,
                                                                 headers={'Content-Type': 'application/xml;version=5.7','If-Match': etg}, auth=HTTPBasicAuth(destun, destpass))
                                        if l3rulreq.status_code == 201:
                                            etg = l3rulreq.headers['ETag']
                                            rucont = l3rulreq.content
                                            ruxml = etree.fromstring(rucont)
                                            for fwlrule in ruxml.iter('rule'):
                                                rulchk.append(fwlrule.attrib["id"])
                                            i += 1
            elif fwlcfg.attrib["type"] == 'LAYER2':
                for child8 in fwlsec.iter('section'):
                    for child9 in child8.findall('rule'):
                        rule.append(etree.tostring(child9))
                        parent = child9.getparent()
                        parent.remove(child9)
                    fwlbdy = etree.tostring(fwlsec).decode()
                    l3req = requests.post(ipl2url, data=xmlheader + fwlbdy,
                                          headers={'Content-Type': 'application/xml;version=5.7'},
                                          auth=HTTPBasicAuth(destun, destpass))
                    if l3req.status_code == 201:
                        secont = l3req.content
                        etg = l3req.headers['ETag']
                        secxml = etree.fromstring(secont)
                        for fwlrulcfg in secxml.iter('section'):
                            secid = fwlrulcfg.attrib["id"]
                            i = 0
                            rulurl = nsx_dbaseurl + dfwl2 + '/' + secid + '/rules'
                            if len(rule) > 0:
                                for i in range(0, len(rule)):
                                    xmlbody3 = xmlheader + rule[i].decode()
                                    l3rulreq = requests.post(rulurl, data=xmlbody3,
                                                             headers={'Content-Type': 'application/xml;version=5.7',
                                                                      'If-Match': etg},
                                                             auth=HTTPBasicAuth(destun, destpass))
                                    if l3rulreq.status_code == 201:
                                        etg = l3rulreq.headers['ETag']
                                        i += 1
                                    elif l3rulreq.status_code == 404:
                                        rulxml = etree.fromstring(rule[i])
                                        for goid in rulxml.findall('.//appliedTo'):
                                            value = goid.find('value').text
                                            if value in ddc.values():
                                                pass
                                            elif value in drp.values():
                                                pass
                                            elif value in dds.values():
                                                pass
                                            elif value in dhs.values():
                                                pass
                                            elif value in dcl.values():
                                                pass
                                            elif value in dvm.values():
                                                pass
                                            elif value in dnw.values():
                                                pass
                                            elif value in dls.values():
                                                pass
                                            elif value in dapps.values():
                                                pass
                                            elif value in dagrp.values():
                                                pass
                                            elif value in dedg.values():
                                                pass
                                            elif value in dips.values():
                                                pass
                                            elif value in desgrp.values():
                                                pass
                                            elif value[:value.find('.')] in diuid.values():
                                                pass
                                            else:
                                                parent = goid.getparent()
                                                parent.remove(goid)
                                        for goid in rulxml.findall('.//source'):
                                            value = goid.find('value').text
                                            if value in ddc.values():
                                                pass
                                            elif value in drp.values():
                                                pass
                                            elif value in dds.values():
                                                pass
                                            elif value in dhs.values():
                                                pass
                                            elif value in dcl.values():
                                                pass
                                            elif value in dvm.values():
                                                pass
                                            elif value in dnw.values():
                                                pass
                                            elif value in dls.values():
                                                pass
                                            elif value in dapps.values():
                                                pass
                                            elif value in dagrp.values():
                                                pass
                                            elif value in dedg.values():
                                                pass
                                            elif value in dips.values():
                                                pass
                                            elif value in desgrp.values():
                                                pass
                                            elif value[:value.find('.')] in diuid.values():
                                                pass
                                            else:
                                                parent = goid.getparent()
                                                parent.remove(goid)
                                        for goid in rulxml.findall('.//destination'):
                                            value = goid.find('value').text
                                            if value in ddc.values():
                                                pass
                                            elif value in drp.values():
                                                pass
                                            elif value in dds.values():
                                                pass
                                            elif value in dhs.values():
                                                pass
                                            elif value in dcl.values():
                                                pass
                                            elif value in dvm.values():
                                                pass
                                            elif value in dnw.values():
                                                pass
                                            elif value in dls.values():
                                                pass
                                            elif value in dapps.values():
                                                pass
                                            elif value in dagrp.values():
                                                pass
                                            elif value in dedg.values():
                                                pass
                                            elif value in dips.values():
                                                pass
                                            elif value in desgrp.values():
                                                pass
                                            elif value[:value.find('.')] in diuid.values():
                                                pass
                                            else:
                                                parent = goid.getparent()
                                                parent.remove(goid)
                                        for goid in rulxml.findall('.//service'):
                                            aid = goid.find('value').text
                                            if aid in dapps.values():
                                                pass
                                            elif aid in dagrp.values():
                                                pass
                                            else:
                                                parent = goid.getparent()
                                                parent.remove(goid)
                                        rulexml = etree.tostring(rulxml)
                                        xmlbody3 = xmlheader + rulexml.decode()
                                        l3rulreq = requests.post(rulurl, data=xmlbody3,
                                                                 headers={'Content-Type': 'application/xml;version=5.7',
                                                                          'If-Match': etg},
                                                                 auth=HTTPBasicAuth(destun, destpass))
                                        if l3rulreq.status_code == 201:
                                            etg = l3rulreq.headers['ETag']
                                            rucont = l3rulreq.content
                                            ruxml = etree.fromstring(rucont)
                                            for fwlrule in ruxml.iter('rule'):
                                                rulchk.append(fwlrule.attrib["id"])
                                            i += 1
            elif fwlcfg.attrib["type"] == 'L3REDIRECT':
                for child8 in fwlsec.iter('section'):
                    for child9 in child8.findall('rule'):
                        rule.append(etree.tostring(child9))
                        parent = child9.getparent()
                        parent.remove(child9)
                    fwlbdy = etree.tostring(fwlsec).decode()
                    l3req = requests.post(ipl3rsurl, data=xmlheader + fwlbdy,
                                          headers={'Content-Type': 'application/xml;version=5.7'},
                                          auth=HTTPBasicAuth(destun, destpass))
                    if l3req.status_code == 201:
                        secont = l3req.content
                        etg = l3req.headers['ETag']
                        secxml = etree.fromstring(secont)
                        for fwlrulcfg in secxml.iter('section'):
                            secid = fwlrulcfg.attrib["id"]
                            i = 0
                            rulurl = nsx_dbaseurl + dfwl3rs + '/' + secid + '/rules'
                            if len(rule) > 0:
                                for i in range(0, len(rule)):
                                    xmlbody3 = xmlheader + rule[i].decode()
                                    l3rulreq = requests.post(rulurl, data=xmlbody3,
                                                             headers={'Content-Type': 'application/xml;version=5.7',
                                                                      'If-Match': etg},
                                                             auth=HTTPBasicAuth(destun, destpass))
                                    if l3rulreq.status_code == 201:
                                        etg = l3rulreq.headers['ETag']
                                        i += 1
                                    elif l3rulreq.status_code == 404:
                                        rulxml = etree.fromstring(rule[i])
                                        for goid in rulxml.findall('.//appliedTo'):
                                            value = goid.find('value').text
                                            if value in ddc.values():
                                                pass
                                            elif value in drp.values():
                                                pass
                                            elif value in dds.values():
                                                pass
                                            elif value in dhs.values():
                                                pass
                                            elif value in dcl.values():
                                                pass
                                            elif value in dvm.values():
                                                pass
                                            elif value in dnw.values():
                                                pass
                                            elif value in dls.values():
                                                pass
                                            elif value in dapps.values():
                                                pass
                                            elif value in dagrp.values():
                                                pass
                                            elif value in dedg.values():
                                                pass
                                            elif value in dips.values():
                                                pass
                                            elif value in desgrp.values():
                                                pass
                                            elif value[:value.find('.')] in diuid.values():
                                                pass
                                            else:
                                                parent = goid.getparent()
                                                parent.remove(goid)
                                        for goid in rulxml.findall('.//source'):
                                            value = goid.find('value').text
                                            if value in ddc.values():
                                                pass
                                            elif value in drp.values():
                                                pass
                                            elif value in dds.values():
                                                pass
                                            elif value in dhs.values():
                                                pass
                                            elif value in dcl.values():
                                                pass
                                            elif value in dvm.values():
                                                pass
                                            elif value in dnw.values():
                                                pass
                                            elif value in dls.values():
                                                pass
                                            elif value in dapps.values():
                                                pass
                                            elif value in dagrp.values():
                                                pass
                                            elif value in dedg.values():
                                                pass
                                            elif value in dips.values():
                                                pass
                                            elif value in desgrp.values():
                                                pass
                                            elif value[:value.find('.')] in diuid.values():
                                                pass
                                            else:
                                                parent = goid.getparent()
                                                parent.remove(goid)
                                        for goid in rulxml.findall('.//destination'):
                                            value = goid.find('value').text
                                            if value in ddc.values():
                                                pass
                                            elif value in drp.values():
                                                pass
                                            elif value in dds.values():
                                                pass
                                            elif value in dhs.values():
                                                pass
                                            elif value in dcl.values():
                                                pass
                                            elif value in dvm.values():
                                                pass
                                            elif value in dnw.values():
                                                pass
                                            elif value in dls.values():
                                                pass
                                            elif value in dapps.values():
                                                pass
                                            elif value in dagrp.values():
                                                pass
                                            elif value in dedg.values():
                                                pass
                                            elif value in dips.values():
                                                pass
                                            elif value in desgrp.values():
                                                pass
                                            elif value[:value.find('.')] in diuid.values():
                                                pass
                                            else:
                                                parent = goid.getparent()
                                                parent.remove(goid)
                                        for goid in rulxml.findall('.//service'):
                                            aid = goid.find('value').text
                                            if aid in dapps.values():
                                                pass
                                            elif aid in dagrp.values():
                                                pass
                                            else:
                                                parent = goid.getparent()
                                                parent.remove(goid)
                                        rulexml = etree.tostring(rulxml)
                                        xmlbody3 = xmlheader + rulexml.decode()
                                        l3rulreq = requests.post(rulurl, data=xmlbody3,
                                                                 headers={'Content-Type': 'application/xml;version=5.7',
                                                                          'If-Match': etg},
                                                                 auth=HTTPBasicAuth(destun, destpass))
                                        if l3rulreq.status_code == 201:
                                            etg = l3rulreq.headers['ETag']
                                            rucont = l3rulreq.content
                                            ruxml = etree.fromstring(rucont)
                                            for fwlrule in ruxml.iter('rule'):
                                                rulchk.append(fwlrule.attrib["id"])
                                            i += 1
    print("##-- DFW rules applied at the destination environment, Please review the settings once again --##")
    time.sleep(3)
    os.system('cls')
    print("vSphere Objects not available at the destination environment is given below")
    print("")
    print("vSphere Objects:",appobjs)
    print("")
    print("Distributed Firewall Rules at the destination environment to be validated are mentioned below")
    print("")
    print("Rules that require manual validation:",rulchk)

def sgcrte():
    print("##-- Gathering Security Group data from the source environment --##")
    xmlheader = '<?xml version="1.0" encoding="UTF-8"?>'
    sapps = getsapps()
    dapps = getapps()
    sagrp = sapgrp()
    dagrp = dapgrp()
    srcgrp = ssgroup()
    desgrp = dsgroup()
    ddc = smoid(viewType=[vim.Datacenter], host=destvc, user=destvcun, pwd=destvcpss, port=dport)
    sdc = smoid(viewType=[vim.Datacenter], host=sourcevc, user=sourcevcun, pwd=sourcevcpss, port=sport)
    drp = smoid(viewType=[vim.ResourcePool], host=destvc, user=destvcun, pwd=destvcpss, port=dport)
    srp = smoid(viewType=[vim.ResourcePool], host=sourcevc, user=sourcevcun, pwd=sourcevcpss, port=sport)
    dds = smoid(viewType=[vim.Datastore], host=destvc, user=destvcun, pwd=destvcpss, port=dport)
    sds = smoid(viewType=[vim.Datastore], host=sourcevc, user=sourcevcun, pwd=sourcevcpss, port=sport)
    dhs = smoid(viewType=[vim.HostSystem], host=destvc, user=destvcun, pwd=destvcpss, port=dport)
    shs = smoid(viewType=[vim.HostSystem], host=sourcevc, user=sourcevcun, pwd=sourcevcpss, port=sport)
    dcl = smoid(viewType=[vim.ComputeResource], host=destvc, user=destvcun, pwd=destvcpss, port=dport)
    scl = smoid(viewType=[vim.ComputeResource], host=sourcevc, user=sourcevcun, pwd=sourcevcpss, port=sport)
    dvm = smoid(viewType=[vim.VirtualMachine], host=destvc, user=destvcun, pwd=destvcpss, port=dport)
    svm = smoid(viewType=[vim.VirtualMachine], host=sourcevc, user=sourcevcun, pwd=sourcevcpss, port=sport)
    dnw = smoid(viewType=[vim.Network], host=destvc, user=destvcun, pwd=destvcpss, port=dport)
    snw = smoid(viewType=[vim.Network], host=sourcevc, user=sourcevcun, pwd=sourcevcpss, port=sport)
    siuid = vmid(viewType=[vim.VirtualMachine], host=sourcevc, user=sourcevcun, pwd=sourcevcpss, port=sport)
    diuid = vmid(viewType=[vim.VirtualMachine], host=destvc, user=destvcun, pwd=destvcpss, port=dport)
    dls = getdls()
    sls = getsls()
    sedg = getedges()
    dedg = getdedges()
    sips = getsipsets()
    dips = getdipsets()
    os.system('cls')
    print("##-- Modifying and Pushing the Security groups XML to the destination environment --##")
    sgurl = nsx_sbaseurl + sg + 'globalroot-0'
    sgreq = requests.get(sgurl, headers={'Content-Type': 'application/*+xml;version=5.7'},
                         auth=HTTPBasicAuth(sourceun, sourcepss))
    cont = sgreq.content
    xml = etree.fromstring(cont)
    for sgrp in xml.iter('objectId'):
        if "securitygroup" in sgrp.text:
            objid = sgrp.text
            objidurl = nsx_sbaseurl + getojid + objid
            objreq = requests.get(objidurl, headers={'Content-Type': 'application/*+xml;version=5.7'},
                                  auth=HTTPBasicAuth(sourceun, sourcepss))
            cont1 = objreq.content
            xml1 = etree.fromstring(cont1)
            for child in xml1.xpath('//vsmUuid'):
                parent = child.getparent()
                parent.remove(child)
                for child1 in xml1.xpath('//nodeId'):
                    parent = child1.getparent()
                    parent.remove(child1)
                    for child2 in xml1.xpath('//revision'):
                        parent = child2.getparent()
                        parent.remove(child2)
                        for child3 in xml1.xpath('//universalRevision'):
                            parent = child3.getparent()
                            parent.remove(child3)
            for goid in xml1.findall('.//member'):
                value = goid.find('objectId').text
                if value in sdc.values():
                    goname = list(sdc.keys())[list(sdc.values()).index(value)]
                    try:
                        goid.find('objectId').text = ddc[goname]
                    except KeyError:
                        parent = goid.getparent()
                        parent.remove(goid)
                elif value in srp.values():
                    goname = list(srp.keys())[list(srp.values()).index(value)]
                    try:
                        goid.find('objectId').text = drp[goname]
                    except KeyError:
                        parent = goid.getparent()
                        parent.remove(goid)
                elif value in sds.values():
                    goname = list(sds.keys())[list(sds.values()).index(value)]
                    try:
                        goid.find('objectId').text = dds[goname]
                    except KeyError:
                        parent = goid.getparent()
                        parent.remove(goid)
                elif value in shs.values():
                    goname = list(shs.keys())[list(shs.values()).index(value)]
                    try:
                        goid.find('objectId').text = dhs[goname]
                    except KeyError:
                        parent = goid.getparent()
                        parent.remove(goid)
                elif value in scl.values():
                    goname = list(scl.keys())[list(scl.values()).index(value)]
                    try:
                        goid.find('objectId').text = dcl[goname]
                    except KeyError:
                        parent = goid.getparent()
                        parent.remove(goid)
                elif value in svm.values():
                    goname = list(svm.keys())[list(svm.values()).index(value)]
                    try:
                        goid.find('objectId').text = dvm[goname]
                    except KeyError:
                        parent = goid.getparent()
                        parent.remove(goid)
                elif value in snw.values():
                    goname = list(snw.keys())[list(snw.values()).index(value)]
                    try:
                        goid.find('objectId').text = dnw[goname]
                    except KeyError:
                        parent = goid.getparent()
                        parent.remove(goid)
                elif value in sls.values():
                    goname = list(sls.keys())[list(sls.values()).index(value)]
                    try:
                        goid.find('objectId').text = dls[goname]
                    except KeyError:
                        parent = goid.getparent()
                        parent.remove(goid)
                elif value in sapps.values():
                    appname = list(sapps.keys())[list(sapps.values()).index(value)]
                    try:
                        goid.find('objectId').text = dapps[appname]
                    except KeyError:
                        parent = goid.getparent()
                        parent.remove(goid)
                elif value in sagrp.values():
                    appname = list(sagrp.keys())[list(sagrp.values()).index(value)]
                    try:
                        goid.find('objectId').text = dagrp[appname]
                    except KeyError:
                        parent = goid.getparent()
                        parent.remove(goid)
                elif value in sedg.values():
                    appname = list(sedg.keys())[list(sedg.values()).index(value)]
                    try:
                        goid.find('objectId').text = dedg[appname]
                    except KeyError:
                        parent = goid.getparent()
                        parent.remove(goid)
                elif value in sips.values():
                    goname = list(sips.keys())[list(sips.values()).index(value)]
                    try:
                        goid.find('objectId').text = dips[goname]
                    except KeyError:
                        parent = goid.getparent()
                        parent.remove(goid)
                elif value in srcgrp.values():
                    goname = list(srcgrp.keys())[list(srcgrp.values()).index(value)]
                    try:
                        goid.find('objectId').text = desgrp[goname]
                    except KeyError:
                        pass
                elif value[:value.find('.')] in siuid.values():
                    goname = list(siuid.keys())[list(siuid.values()).index(value[:value.find('.')])]
                    uidsuffix = value[value.find('.'):]
                    try:
                        duid = diuid[goname]
                        vnicid = duid + uidsuffix
                        goid.find('objectId').text = vnicid
                    except KeyError:
                        parent = goid.getparent()
                        parent.remove(goid)
            for goid in xml1.findall('.//excludeMember'):
                value = goid.find('objectId').text
                if value in sdc.values():
                    goname = list(sdc.keys())[list(sdc.values()).index(value)]
                    try:
                        goid.find('objectId').text = ddc[goname]
                    except KeyError:
                        parent = goid.getparent()
                        parent.remove(goid)
                elif value in srp.values():
                    goname = list(srp.keys())[list(srp.values()).index(value)]
                    try:
                        goid.find('objectId').text = drp[goname]
                    except KeyError:
                        parent = goid.getparent()
                        parent.remove(goid)
                elif value in sds.values():
                    goname = list(sds.keys())[list(sds.values()).index(value)]
                    try:
                        goid.find('objectId').text = dds[goname]
                    except KeyError:
                        parent = goid.getparent()
                        parent.remove(goid)
                elif value in shs.values():
                    goname = list(shs.keys())[list(shs.values()).index(value)]
                    try:
                        goid.find('objectId').text = dhs[goname]
                    except KeyError:
                        parent = goid.getparent()
                        parent.remove(goid)
                elif value in scl.values():
                    goname = list(scl.keys())[list(scl.values()).index(value)]
                    try:
                        goid.find('objectId').text = dcl[goname]
                    except KeyError:
                        parent = goid.getparent()
                        parent.remove(goid)
                elif value in svm.values():
                    goname = list(svm.keys())[list(svm.values()).index(value)]
                    try:
                        goid.find('objectId').text = dvm[goname]
                    except KeyError:
                        parent = goid.getparent()
                        parent.remove(goid)
                elif value in snw.values():
                    goname = list(snw.keys())[list(snw.values()).index(value)]
                    try:
                        goid.find('objectId').text = dnw[goname]
                    except KeyError:
                        parent = goid.getparent()
                        parent.remove(goid)
                elif value in sls.values():
                    goname = list(sls.keys())[list(sls.values()).index(value)]
                    try:
                        goid.find('objectId').text = dls[goname]
                    except KeyError:
                        parent = goid.getparent()
                        parent.remove(goid)
                elif value in sapps.values():
                    appname = list(sapps.keys())[list(sapps.values()).index(value)]
                    try:
                        goid.find('objectId').text = dapps[appname]
                    except KeyError:
                        parent = goid.getparent()
                        parent.remove(goid)
                elif value in sagrp.values():
                    appname = list(sagrp.keys())[list(sagrp.values()).index(value)]
                    try:
                        goid.find('objectId').text = dagrp[appname]
                    except KeyError:
                        parent = goid.getparent()
                        parent.remove(goid)
                elif value in sedg.values():
                    appname = list(sedg.keys())[list(sedg.values()).index(value)]
                    try:
                        goid.find('objectId').text = dedg[appname]
                    except KeyError:
                        parent = goid.getparent()
                        parent.remove(goid)
                elif value in sips.values():
                    goname = list(sips.keys())[list(sips.values()).index(value)]
                    try:
                        goid.find('objectId').text = dips[goname]
                    except KeyError:
                        parent = goid.getparent()
                        parent.remove(goid)
                elif value in srcgrp.values():
                    goname = list(srcgrp.keys())[list(srcgrp.values()).index(value)]
                    try:
                        goid.find('objectId').text = desgrp[goname]
                    except KeyError:
                        pass
                elif value[:value.find('.')] in siuid.values():
                    goname = list(siuid.keys())[list(siuid.values()).index(value[:value.find('.')])]
                    uidsuffix = value[value.find('.'):]
                    try:
                        duid = diuid[goname]
                        vnicid = duid + uidsuffix
                        goid.find('objectId').text = vnicid
                    except KeyError:
                        parent = goid.getparent()
                        parent.remove(goid)
            for goid in xml1.iter('dynamicCriteria'):
                if goid.find('value') != None and goid.find('object/objectId') != None:
                    value = goid.find('object/objectId').text
                    if value in sdc.values():
                        goname = list(sdc.keys())[list(sdc.values()).index(value)]
                        try:
                            goid.find('object/objectId').text = ddc[goname]
                            goid.find('value').text = ddc[goname]
                        except KeyError:
                            parent = goid.getparent()
                            parent.remove(goid)
                    elif value in srp.values():
                        goname = list(srp.keys())[list(srp.values()).index(value)]
                        try:
                            goid.find('object/objectId').text = drp[goname]
                            goid.find('value').text = drp[goname]
                        except KeyError:
                            parent = goid.getparent()
                            parent.remove(goid)
                    elif value in sds.values():
                        goname = list(sds.keys())[list(sds.values()).index(value)]
                        try:
                            goid.find('object/objectId').text = dds[goname]
                            goid.find('value').text = dds[goname]
                        except KeyError:
                            parent = goid.getparent()
                            parent.remove(goid)
                    elif value in shs.values():
                        goname = list(shs.keys())[list(shs.values()).index(value)]
                        try:
                            goid.find('object/objectId').text = dhs[goname]
                            goid.find('value').text = dhs[goname]
                        except KeyError:
                            parent = goid.getparent()
                            parent.remove(goid)
                    elif value in scl.values():
                        goname = list(scl.keys())[list(scl.values()).index(value)]
                        try:
                            goid.find('object/objectId').text = dcl[goname]
                            goid.find('value').text = dcl[goname]
                        except KeyError:
                            parent = goid.getparent()
                            parent.remove(goid)
                    elif value in svm.values():
                        goname = list(svm.keys())[list(svm.values()).index(value)]
                        try:
                            goid.find('object/objectId').text = dvm[goname]
                            goid.find('value').text = dvm[goname]
                        except KeyError:
                            parent = goid.getparent()
                            parent.remove(goid)
                    elif value in snw.values():
                        goname = list(snw.keys())[list(snw.values()).index(value)]
                        try:
                            goid.find('object/objectId').text = dnw[goname]
                            goid.find('value').text = dnw[goname]
                        except KeyError:
                            parent = goid.getparent()
                            parent.remove(goid)
                    elif value in sls.values():
                        goname = list(sls.keys())[list(sls.values()).index(value)]
                        try:
                            goid.find('object/objectId').text = dls[goname]
                            goid.find('value').text = dls[goname]
                        except KeyError:
                            parent = goid.getparent()
                            parent.remove(goid)
                    elif value in sapps.values():
                        appname = list(sapps.keys())[list(sapps.values()).index(value)]
                        try:
                            goid.find('object/objectId').text = dapps[appname]
                            goid.find('value').text = dapps[appname]
                        except KeyError:
                            parent = goid.getparent()
                            parent.remove(goid)
                    elif value in sagrp.values():
                        appname = list(sagrp.keys())[list(sagrp.values()).index(value)]
                        try:
                            goid.find('object/objectId').text = dagrp[appname]
                            goid.find('value').text = dagrp[appname]
                        except KeyError:
                            parent = goid.getparent()
                            parent.remove(goid)
                    elif value in sedg.values():
                        appname = list(sedg.keys())[list(sedg.values()).index(value)]
                        try:
                            goid.find('object/objectId').text = dedg[appname]
                            goid.find('value').text = dedg[appname]
                        except KeyError:
                            parent = goid.getparent()
                            parent.remove(goid)
                    elif value in sips.values():
                        goname = list(sips.keys())[list(sips.values()).index(value)]
                        try:
                            goid.find('object/objectId').text = dips[goname]
                            goid.find('value').text = dips[goname]
                        except KeyError:
                            parent = goid.getparent()
                            parent.remove(goid)
                    elif value in srcgrp.values():
                        goname = list(srcgrp.keys())[list(srcgrp.values()).index(value)]
                        try:
                            goid.find('object/objectId').text = desgrp[goname]
                            goid.find('value').text = desgrp[goname]
                        except KeyError:
                            pass
                    elif value[:value.find('.')] in siuid.values():
                        goname = list(siuid.keys())[list(siuid.values()).index(value[:value.find('.')])]
                        uidsuffix = value[value.find('.'):]
                        try:
                            duid = diuid[goname]
                            vnicid = duid + uidsuffix
                            goid.find('object/objectId').text = vnicid
                            goid.find('value').text = vnicid
                        except KeyError:
                            parent = goid.getparent()
                            parent.remove(goid)
            sgroup1 = (b''.join(map(etree.tostring, xml1))).strip().decode()
            objpsturl = nsx_dbaseurl + sgpost + 'globalroot-0'
            requests.post(objpsturl, data=xmlheader + '<securitygroup>' + sgroup1 + '</securitygroup>',
                          headers={'Content-Type': 'application/xml;version=5.7'},
                          auth=HTTPBasicAuth(destun, destpass))
            desgrp = dsgroup()
            sgurl = nsx_sbaseurl + sg + 'globalroot-0'
            sgreq = requests.get(sgurl, headers={'Content-Type': 'application/*+xml;version=5.7'},
                                 auth=HTTPBasicAuth(sourceun, sourcepss))
            cont = sgreq.content
            xml = etree.fromstring(cont)
            for sgrp in xml.iter('objectId'):
                if "securitygroup" in sgrp.text:
                    objid = sgrp.text
                    objidurl = nsx_sbaseurl + getojid + objid
                    objreq = requests.get(objidurl, headers={'Content-Type': 'application/*+xml;version=5.7'},
                                          auth=HTTPBasicAuth(sourceun, sourcepss))
                    cont1 = objreq.content
                    xml1 = etree.fromstring(cont1)
                    for child in xml1.xpath('//vsmUuid'):
                        parent = child.getparent()
                        parent.remove(child)
                        for child1 in xml1.xpath('//nodeId'):
                            parent = child1.getparent()
                            parent.remove(child1)
                            for child2 in xml1.xpath('//revision'):
                                parent = child2.getparent()
                                parent.remove(child2)
                                for child3 in xml1.xpath('//universalRevision'):
                                    parent = child3.getparent()
                                    parent.remove(child3)
                    for goid in xml1.findall('.//member'):
                        value = goid.find('objectId').text
                        if value in sdc.values():
                            goname = list(sdc.keys())[list(sdc.values()).index(value)]
                            try:
                                goid.find('objectId').text = ddc[goname]
                            except KeyError:
                                parent = goid.getparent()
                                parent.remove(goid)
                        elif value in srp.values():
                            goname = list(srp.keys())[list(srp.values()).index(value)]
                            try:
                                goid.find('objectId').text = drp[goname]
                            except KeyError:
                                parent = goid.getparent()
                                parent.remove(goid)
                        elif value in sds.values():
                            goname = list(sds.keys())[list(sds.values()).index(value)]
                            try:
                                goid.find('objectId').text = dds[goname]
                            except KeyError:
                                parent = goid.getparent()
                                parent.remove(goid)
                        elif value in shs.values():
                            goname = list(shs.keys())[list(shs.values()).index(value)]
                            try:
                                goid.find('objectId').text = dhs[goname]
                            except KeyError:
                                parent = goid.getparent()
                                parent.remove(goid)
                        elif value in scl.values():
                            goname = list(scl.keys())[list(scl.values()).index(value)]
                            try:
                                goid.find('objectId').text = dcl[goname]
                            except KeyError:
                                parent = goid.getparent()
                                parent.remove(goid)
                        elif value in svm.values():
                            goname = list(svm.keys())[list(svm.values()).index(value)]
                            try:
                                goid.find('objectId').text = dvm[goname]
                            except KeyError:
                                parent = goid.getparent()
                                parent.remove(goid)
                        elif value in snw.values():
                            goname = list(snw.keys())[list(snw.values()).index(value)]
                            try:
                                goid.find('objectId').text = dnw[goname]
                            except KeyError:
                                parent = goid.getparent()
                                parent.remove(goid)
                        elif value in sls.values():
                            goname = list(sls.keys())[list(sls.values()).index(value)]
                            try:
                                goid.find('objectId').text = dls[goname]
                            except KeyError:
                                parent = goid.getparent()
                                parent.remove(goid)
                        elif value in sapps.values():
                            appname = list(sapps.keys())[list(sapps.values()).index(value)]
                            try:
                                goid.find('objectId').text = dapps[appname]
                            except KeyError:
                                parent = goid.getparent()
                                parent.remove(goid)
                        elif value in sagrp.values():
                            appname = list(sagrp.keys())[list(sagrp.values()).index(value)]
                            try:
                                goid.find('objectId').text = dagrp[appname]
                            except KeyError:
                                parent = goid.getparent()
                                parent.remove(goid)
                        elif value in sedg.values():
                            appname = list(sedg.keys())[list(sedg.values()).index(value)]
                            try:
                                goid.find('objectId').text = dedg[appname]
                            except KeyError:
                                parent = goid.getparent()
                                parent.remove(goid)
                        elif value in sips.values():
                            goname = list(sips.keys())[list(sips.values()).index(value)]
                            try:
                                goid.find('objectId').text = dips[goname]
                            except KeyError:
                                parent = goid.getparent()
                                parent.remove(goid)
                        elif value in srcgrp.values():
                            goname = list(srcgrp.keys())[list(srcgrp.values()).index(value)]
                            try:
                                goid.find('objectId').text = desgrp[goname]
                            except KeyError:
                                pass
                        elif value[:value.find('.')] in siuid.values():
                            goname = list(siuid.keys())[list(siuid.values()).index(value[:value.find('.')])]
                            uidsuffix = value[value.find('.'):]
                            try:
                                duid = diuid[goname]
                                vnicid = duid + uidsuffix
                                goid.find('objectId').text = vnicid
                            except KeyError:
                                parent = goid.getparent()
                                parent.remove(goid)
                    for goid in xml1.findall('.//excludeMember'):
                        value = goid.find('objectId').text
                        if value in sdc.values():
                            goname = list(sdc.keys())[list(sdc.values()).index(value)]
                            try:
                                goid.find('objectId').text = ddc[goname]
                            except KeyError:
                                parent = goid.getparent()
                                parent.remove(goid)
                        elif value in srp.values():
                            goname = list(srp.keys())[list(srp.values()).index(value)]
                            try:
                                goid.find('objectId').text = drp[goname]
                            except KeyError:
                                parent = goid.getparent()
                                parent.remove(goid)
                        elif value in sds.values():
                            goname = list(sds.keys())[list(sds.values()).index(value)]
                            try:
                                goid.find('objectId').text = dds[goname]
                            except KeyError:
                                parent = goid.getparent()
                                parent.remove(goid)
                        elif value in shs.values():
                            goname = list(shs.keys())[list(shs.values()).index(value)]
                            try:
                                goid.find('objectId').text = dhs[goname]
                            except KeyError:
                                parent = goid.getparent()
                                parent.remove(goid)
                        elif value in scl.values():
                            goname = list(scl.keys())[list(scl.values()).index(value)]
                            try:
                                goid.find('objectId').text = dcl[goname]
                            except KeyError:
                                parent = goid.getparent()
                                parent.remove(goid)
                        elif value in svm.values():
                            goname = list(svm.keys())[list(svm.values()).index(value)]
                            try:
                                goid.find('objectId').text = dvm[goname]
                            except KeyError:
                                parent = goid.getparent()
                                parent.remove(goid)
                        elif value in snw.values():
                            goname = list(snw.keys())[list(snw.values()).index(value)]
                            try:
                                goid.find('objectId').text = dnw[goname]
                            except KeyError:
                                parent = goid.getparent()
                                parent.remove(goid)
                        elif value in sls.values():
                            goname = list(sls.keys())[list(sls.values()).index(value)]
                            try:
                                goid.find('objectId').text = dls[goname]
                            except KeyError:
                                parent = goid.getparent()
                                parent.remove(goid)
                        elif value in sapps.values():
                            appname = list(sapps.keys())[list(sapps.values()).index(value)]
                            try:
                                goid.find('objectId').text = dapps[appname]
                            except KeyError:
                                parent = goid.getparent()
                                parent.remove(goid)
                        elif value in sagrp.values():
                            appname = list(sagrp.keys())[list(sagrp.values()).index(value)]
                            try:
                                goid.find('objectId').text = dagrp[appname]
                            except KeyError:
                                parent = goid.getparent()
                                parent.remove(goid)
                        elif value in sedg.values():
                            appname = list(sedg.keys())[list(sedg.values()).index(value)]
                            try:
                                goid.find('objectId').text = dedg[appname]
                            except KeyError:
                                parent = goid.getparent()
                                parent.remove(goid)
                        elif value in sips.values():
                            goname = list(sips.keys())[list(sips.values()).index(value)]
                            try:
                                goid.find('objectId').text = dips[goname]
                            except KeyError:
                                parent = goid.getparent()
                                parent.remove(goid)
                        elif value in srcgrp.values():
                            goname = list(srcgrp.keys())[list(srcgrp.values()).index(value)]
                            try:
                                goid.find('objectId').text = desgrp[goname]
                            except KeyError:
                                pass
                        elif value[:value.find('.')] in siuid.values():
                            goname = list(siuid.keys())[list(siuid.values()).index(value[:value.find('.')])]
                            uidsuffix = value[value.find('.'):]
                            try:
                                duid = diuid[goname]
                                vnicid = duid + uidsuffix
                                goid.find('objectId').text = vnicid
                            except KeyError:
                                parent = goid.getparent()
                                parent.remove(goid)
                    for goid in xml1.iter('dynamicCriteria'):
                        if goid.find('value') != None and goid.find('object/objectId') != None:
                            value = goid.find('object/objectId').text
                            if value in sdc.values():
                                goname = list(sdc.keys())[list(sdc.values()).index(value)]
                                try:
                                    goid.find('object/objectId').text = ddc[goname]
                                    goid.find('value').text = ddc[goname]
                                except KeyError:
                                    parent = goid.getparent()
                                    parent.remove(goid)
                            elif value in srp.values():
                                goname = list(srp.keys())[list(srp.values()).index(value)]
                                try:
                                    goid.find('object/objectId').text = drp[goname]
                                    goid.find('value').text = drp[goname]
                                except KeyError:
                                    parent = goid.getparent()
                                    parent.remove(goid)
                            elif value in sds.values():
                                goname = list(sds.keys())[list(sds.values()).index(value)]
                                try:
                                    goid.find('object/objectId').text = dds[goname]
                                    goid.find('value').text = dds[goname]
                                except KeyError:
                                    parent = goid.getparent()
                                    parent.remove(goid)
                            elif value in shs.values():
                                goname = list(shs.keys())[list(shs.values()).index(value)]
                                try:
                                    goid.find('object/objectId').text = dhs[goname]
                                    goid.find('value').text = dhs[goname]
                                except KeyError:
                                    parent = goid.getparent()
                                    parent.remove(goid)
                            elif value in scl.values():
                                goname = list(scl.keys())[list(scl.values()).index(value)]
                                try:
                                    goid.find('object/objectId').text = dcl[goname]
                                    goid.find('value').text = dcl[goname]
                                except KeyError:
                                    parent = goid.getparent()
                                    parent.remove(goid)
                            elif value in svm.values():
                                goname = list(svm.keys())[list(svm.values()).index(value)]
                                try:
                                    goid.find('object/objectId').text = dvm[goname]
                                    goid.find('value').text = dvm[goname]
                                except KeyError:
                                    parent = goid.getparent()
                                    parent.remove(goid)
                            elif value in snw.values():
                                goname = list(snw.keys())[list(snw.values()).index(value)]
                                try:
                                    goid.find('object/objectId').text = dnw[goname]
                                    goid.find('value').text = dnw[goname]
                                except KeyError:
                                    parent = goid.getparent()
                                    parent.remove(goid)
                            elif value in sls.values():
                                goname = list(sls.keys())[list(sls.values()).index(value)]
                                try:
                                    goid.find('object/objectId').text = dls[goname]
                                    goid.find('value').text = dls[goname]
                                except KeyError:
                                    parent = goid.getparent()
                                    parent.remove(goid)
                            elif value in sapps.values():
                                appname = list(sapps.keys())[list(sapps.values()).index(value)]
                                try:
                                    goid.find('object/objectId').text = dapps[appname]
                                    goid.find('value').text = dapps[appname]
                                except KeyError:
                                    parent = goid.getparent()
                                    parent.remove(goid)
                            elif value in sagrp.values():
                                appname = list(sagrp.keys())[list(sagrp.values()).index(value)]
                                try:
                                    goid.find('object/objectId').text = dagrp[appname]
                                    goid.find('value').text = dagrp[appname]
                                except KeyError:
                                    parent = goid.getparent()
                                    parent.remove(goid)
                            elif value in sedg.values():
                                appname = list(sedg.keys())[list(sedg.values()).index(value)]
                                try:
                                    goid.find('object/objectId').text = dedg[appname]
                                    goid.find('value').text = dedg[appname]
                                except KeyError:
                                    parent = goid.getparent()
                                    parent.remove(goid)
                            elif value in sips.values():
                                goname = list(sips.keys())[list(sips.values()).index(value)]
                                try:
                                    goid.find('object/objectId').text = dips[goname]
                                    goid.find('value').text = dips[goname]
                                except KeyError:
                                    parent = goid.getparent()
                                    parent.remove(goid)
                            elif value in srcgrp.values():
                                goname = list(srcgrp.keys())[list(srcgrp.values()).index(value)]
                                try:
                                    goid.find('object/objectId').text = desgrp[goname]
                                    goid.find('value').text = desgrp[goname]
                                except KeyError:
                                    pass
                            elif value[:value.find('.')] in siuid.values():
                                goname = list(siuid.keys())[list(siuid.values()).index(value[:value.find('.')])]
                                uidsuffix = value[value.find('.'):]
                                try:
                                    duid = diuid[goname]
                                    vnicid = duid + uidsuffix
                                    goid.find('object/objectId').text = vnicid
                                    goid.find('value').text = vnicid
                                except KeyError:
                                    parent = goid.getparent()
                                    parent.remove(goid)
                    sgroup1 = (b''.join(map(etree.tostring, xml1))).strip().decode()
                    objpsturl = nsx_dbaseurl + sgpost + 'globalroot-0'
                    requests.post(objpsturl, data=xmlheader + '<securitygroup>' + sgroup1 + '</securitygroup>',
                                  headers={'Content-Type': 'application/xml;version=5.7'},
                                  auth=HTTPBasicAuth(destun, destpass))
    print("##-- Security groups has been created at the destination side --##")
    time.sleep(5)
    spcrte()

def spcrte():
    os.system('cls')
    print("##-- Gathering Security policy data from the source environment --##")
    srcgrp = ssgroup()
    desgrp = dsgroup()
    srcsg = scspolicy()
    dessg = scdpolicy()
    xmlheader = '<?xml version="1.0" encoding="UTF-8"?>'
    spurl = nsx_sbaseurl+spfwget
    spdurl = nsx_dbaseurl + spfwget
    spreq = requests.get(spurl, headers = {'Content-Type': 'application/*+xml;version=5.7'}, auth=HTTPBasicAuth(sourceun, sourcepss))
    cont = spreq.content
    xml = etree.fromstring(cont)
    appt = xml.find('appliedTo').text
    xmlbody = xmlheader+'<SecurityPolicyFirewallConfig><appliedTo>'+appt+'</appliedTo></SecurityPolicyFirewallConfig>'
    requests.put(spdurl, data=xmlbody, headers = {'Content-Type': 'application/xml;version=5.7'}, auth=HTTPBasicAuth(destun, destpass))
    scsurl = nsx_sbaseurl+scpl+'/all?startIndex=0&pageSize=1024'
    scdurl = nsx_dbaseurl + scpl
    screq = requests.get(scsurl, headers={'Content-Type': 'application/*+xml;version=5.7'},
                         auth=HTTPBasicAuth(sourceun, sourcepss))
    cont = screq.content
    xml = etree.fromstring(cont)
    for child in xml.xpath('//vsmUuid'):
        parent = child.getparent()
        parent.remove(child)
        for child1 in xml.xpath('//nodeId'):
            parent = child1.getparent()
            parent.remove(child1)
            for child2 in xml.xpath('//securityPolicy/objectId'):
                parent = child2.getparent()
                parent.remove(child2)
                for child3 in xml.xpath('//action/objectId'):
                    parent = child3.getparent()
                    parent.remove(child3)
                    for child4 in xml.xpath('//revision'):
                        parent = child4.getparent()
                        parent.remove(child4)
                        for child5 in xml.xpath('//universalRevision'):
                            parent = child5.getparent()
                            parent.remove(child5)
    for sgrp in xml.iter('objectId'):
        if "securitygroup" in sgrp.text:
            objid = sgrp.text
            if objid in srcgrp.values():
                goname = list(srcgrp.keys())[list(srcgrp.values()).index(objid)]
                try:
                    sgrp.text = desgrp[goname]
                except KeyError:
                    pass
    for spolicy in xml.iter('securityPolicy'):
        scxml = etree.tostring(spolicy).decode()
        xmlbody1 = xmlheader + scxml
        scdreq = requests.post(scdurl, data=xmlbody1, headers = {'Content-Type': 'application/xml;version=5.7'}, auth=HTTPBasicAuth(destun, destpass))
        srcsg = scspolicy()
        dessg = scdpolicy()
        for sgrp in xml.iter('objectId'):
            if "policy-" in sgrp.text:
                objid = sgrp.text
                if objid in srcsg.values():
                    goname = list(srcsg.keys())[list(srcsg.values()).index(objid)]
                    try:
                        sgrp.text = dessg[goname]
                    except KeyError:
                        pass
                    for spolicy in xml.iter('securityPolicy'):
                        scxml = etree.tostring(spolicy).decode()
                        xmlbody1 = xmlheader + scxml
                        scdreq = requests.post(scdurl, data=xmlbody1,
                                               headers={'Content-Type': 'application/xml;version=5.7'},
                                               auth=HTTPBasicAuth(destun, destpass))
    print('##-- Created and applied Security policies at the destination --##')

if __name__ == '__main__':
    userinput() 

