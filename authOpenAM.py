#!/usr/bin/env python3



import requests

import json

import boto3

import botocore

from botocore.client import Config

import sys

from bs4 import BeautifulSoup

import base64

import xml.etree.ElementTree as ET

import datetime

import dateutil

import pickle

from tkinter import ttk



forcecli = False  # Debug on a GUI enabled workstation

try:

    import Tkinter as tk

    #print('Tkinter success')

except ImportError:

    try:

        import tkinter as tk

        #print('tkinter success')

    except ImportError:

        #print('No tk')

        forcecli=True

        class tk:

            class TclError():

                pass

try:

    import ConfigParser as cp

except ImportError:

    import configparser as cp

import os

import getpass



ret_credentials = {}

selectedroleindex = 0

debug = False

test = False



# Unmodified import from billing script

accountFriendlyNames = {

    '400006844420': {'name': 'Central Billing', 'cc': '6434', 'pd': 'Infrastructure', 'stage': 'PROD'},

    '322653911670': {'name': 'Shared Sandbox', 'cc:': '6434', 'pd': 'Sandbox', 'stage': 'DEV'},

    '367833535743': {'name': 'Shared Production', 'cc': '6434', 'pd': 'Infrastructure', 'stage': 'PROD'},

    '660566219893': {'name': 'Shared Production Dev', 'cc': '6434', 'pd': 'Infrastructure'},

    '448297749429': {'name': 'Central Audit', 'cc': '6612', 'pd': 'Infrastructure', 'stage': 'PROD'},

    '991185673689': {'name': 'Keymanagement', 'cc': '6612', 'pd': 'Security', 'stage': 'PROD'},

    '723231037150': {'name': 'Product Development', 'stage': 'DEV'},

    '022171590975': {'name': 'Product Test', 'stage': 'TEST'},

    '466578325253': {'name': 'Product Simulation', 'stage': 'SIM'},

    '063412041729': {'name': 'Product Production', 'stage': 'PROD'},

    '933815432209': {'name': 'Product Lab', 'pd': 'PDL', 'stage': 'DEV'},

    '871424137820': {'name': 'Public Dataset Staging', 'pd': 'PDL', 'cc': '6522', 'stage': 'TEST'},

    '496937891530': {'name': 'Public Dataset Production', 'pd': 'PDL', 'cc': '6522', 'stage': 'PROD'},

    '249941378896': {'name': 'Digital Business Platform Development', 'pd': 'PDL', 'cc': '6522', 'stage': 'DEV'},

    '453335626254': {'name': 'Digital Business Platform Simulation', 'pd': 'PDL', 'cc': '6522', 'stage': 'SIM'},

    '165637739523': {'name': 'Digital Business Platform Production', 'pd': 'PDL', 'cc': '6522', 'stage': 'PROD'},

    '147020635585': {'name': 'Service Zone', 'stage': 'PROD'},

    '133771832446': {'name': 'SAP Development', 'cc': '6362', 'pd': 'CorpSystem', 'stage': 'DEV'},

    '688688701977': {'name': 'Storage', 'stage': 'PROD'},

    '569029537724': {'name': 'Clearstream DR', 'cc': 'CBL-DR*'},                # Cancelled

    '147465817531': {'name': 'Data Development', 'pd': 'PDL', 'cc': '6522'},    # Cancelled

    '993074466952': {'name': 'Data Simulation', 'pd': 'PDL', 'cc': '6522'},     # Cancelled

    '399229768930': {'name': 'Spare', 'pd': 'Infrastructure', 'cc': '6434', 'stage': 'DEV'},

    '931366819408': {'name': 'Derivatives Development', 'pd': 'Derivatives', 'cc': '6181', 'stage': 'DEV'},

    '974035090006': {'name': 'Derivatives Test', 'pd': 'Derivatives', 'cc': '6181', 'stage': 'TEST'},

    '611775349707': {'name': 'Derivatives Simulation', 'pd': 'Derivatives', 'cc': '6181', 'stage': 'SIM'},

    '446878570862': {'name': 'Derivatives Production', 'pd': 'Derivatives', 'cc': '6181', 'stage': 'PROD'},

    '479958727785': {'name': 'Energy Development', 'pd': 'Energy', 'cc': '6313', 'stage': 'DEV'},

    '795834934212': {'name': 'Energy Test', 'pd': 'Energy', 'cc': '6313', 'stage': 'TEST'},

    '572154689331': {'name': 'Energy Simulation', 'pd': 'Energy', 'cc': '6313', 'stage': 'SIM'},

    '911593344232': {'name': 'Energy Production', 'pd': 'Energy', 'cc': '6313', 'stage': 'PROD'},

    '438193686961': {'name': 'CloudSim Staging', 'pd': 'Derivatives', 'cc': '64281000', 'stage': 'SIM'},

    '238730450445': {'name': 'CloudSim Development', 'pd': 'Derivatives', 'cc': '64281000', 'stage': 'DEV'},

    '694812722537': {'name': 'CloudSim Production', 'pd': 'Derivatives', 'cc': '64281000', 'stage': 'PROD'},

    '900850023817': {'name': 'FX Staging', 'pd': 'FX', 'cc': '00000000', 'stage': 'SIM'},

    '367632884565': {'name': 'FX Development', 'pd': 'FX', 'cc': '00000000', 'stage': 'DEV'},

    '896862121835': {'name': 'FX Production', 'pd': 'FX', 'cc': '00000000', 'stage': 'PROD'},

    '320524105305': {'name': 'Nodal', 'pd': 'Derivatives', 'cc': '6181', 'stage': 'DEV'},

    '923118874442': {'name': 'Product Lab Data', 'pd': 'Data', 'cc': '1406', 'stage': 'DEV'},

    '153468451607': {'name': 'Managed Services', 'pd': 'Managed Services', 'cc': '51241188', 'stage': 'PROD'},

    '068243689374': {'name': 'Finologee', 'pd': 'Managed Services', 'cc': '51241188', 'stage': 'PROD'}, # cancelled

    '790734867021': {'name': 'Training', 'cc': '6434', 'pd': 'Infrastructure', 'stage': 'DEV'}, # cancelled

    '433913383297': {'name': 'Forensics', 'cc': '6434', 'pd': 'Infrastructure', 'stage': 'PROD'},

    '421085808656': {'name': 'Public Data Set'},                                # Not billed

    '904826209147': {'name': 'Clearstream C4C', 'cc': 'C4C-synthetic'},

    '617885025151': {'name': 'Clearstream C4C', 'cc': 'C4C-synthetic'},

    '575471454360': {'name': 'Clearstream C4C', 'cc': 'C4C-synthetic'},

    '169542301831': {'name': 'Clearstream C4C', 'cc': 'C4C-synthetic'},

    '799184604449': {'name': 'Clearing Workspaces', 'pd': 'Clearing', 'cc': '6121', 'stage': 'DEV'},

    '322893446712': {'name': 'Clearing Development', 'pd': 'Clearing', 'cc': '6121', 'stage': 'DEV'},

    '966410276232': {'name': 'Clearing Test', 'pd': 'Clearing', 'cc': '6121', 'stage': 'DEV'},

    '274833747064': {'name': 'Clearing Simulation', 'pd': 'Clearing', 'cc': '6121', 'stage': 'PROD'},

    '782970146897': {'name': 'Clearing Production', 'pd': 'Clearing', 'cc': '6121', 'stage': 'PROD'},

    '725084637837': {'name': 'StatistiX Development', 'pd': 'StatistiX', 'cc': 'PSP 0001/P9-00369', 'stage': 'DEV'},

    '804702933086': {'name': 'StatistiX Test', 'pd': 'StatistiX', 'cc': 'PSP 0001/P9-00369', 'stage': 'DEV'},

    '103430931956': {'name': 'StatistiX Simulation', 'pd': 'StatistiX', 'cc': 'PSP 0001/P9-00369', 'stage': 'PROD'},

    '661043264943': {'name': 'StatistiX Production', 'pd': 'StatistiX', 'cc': 'PSP 0001/P9-00369', 'stage': 'PROD'},

    '412062962289': {'name': 'Buyin Development', 'pd': 'Derivatives', 'cc': '6181', 'stage': 'DEV'},

    '605241658156': {'name': 'Buyin Test', 'pd': 'Derivatives', 'cc': '6181', 'stage': 'DEV'},

    '348201910803': {'name': 'Buyin Simulation', 'pd': 'Derivatives', 'cc': '6181', 'stage': 'PROD'},

    '483172741429': {'name': 'Buyin Production', 'pd': 'Derivatives', 'cc': '6181', 'stage': 'PROD'},

    '941064761444': {'name': 'Data Development', 'pd': 'Data', 'cc': '6141', 'stage': 'DEV'},

    '775028022029': {'name': 'Data Test', 'pd': 'Data', 'cc': '6141', 'stage': 'DEV'},

    '189699312445': {'name': 'Data Simulation', 'pd': 'Data', 'cc': '6141', 'stage': 'PROD'},

    '117467446506': {'name': 'Data Production', 'pd': 'Data', 'cc': '6141', 'stage': 'PROD'},

    '086083609425': {'name': 'VMC PoC', 'cc': '6436', 'pd': 'Infrastructure', 'stage': 'PROD'},

    '213967156576': {'name': 'Risk Simulation', 'pd': 'Risk', 'cc': '6213', 'stage': 'PROD'},

    '307775487682': {'name': 'Risk Production', 'pd': 'Risk', 'cc': '6213', 'stage': 'PROD'},

    '414712327780': {'name': 'Risk Test', 'pd': 'Risk', 'cc': '6213', 'stage': 'DEV'},

    '623392775524': {'name': 'Risk Development', 'pd': 'Risk', 'cc': '6213', 'stage': 'DEV'},

    '913420853066': {'name': 'Training Apprentices', 'cc': '6436', 'pd': 'Infrastructure', 'stage': 'PROD'},

    'undefined':    {'name': 'Undefined', 'stage': 'unknown'}

}



os.path.normpath('/.aws/credentials')

configfilename = os.path.join(os.path.expanduser('~'), '.aws', 'credentials')

auth_cache_file = os.path.join(os.path.expanduser('~'), '.assumedRole.pkl')     # AWS Credentials cache file



if test:

    baseurl = 'https://amdfis.deutsche-boerse.com/auth/'

    idp = 'idp1'

else:

    baseurl = 'https://amplis.deutsche-boerse.com/auth/'

    idp = 'idp'





def auth_cached():

    try:

        with open(auth_cache_file, 'rb') as input:

            assumedRoleObject = pickle.load(input)

        credentials = assumedRoleObject['Credentials']

    except:

        return None



    return credentials





def auth_live():

    global selectedroleindex

    url = baseurl + 'json/authenticate'

    if test:

        payload = {

            'authIndexType': 'service',

            'authIndexValue': 'L10',

            'realm': '/internet',

            'spEntityID': 'urn:amazon:webservices',

            'goto': 'https://amdfis.deutsche-boerse.com/auth/saml2/jsp/idpSSOInit.jsp?metaAlias=/internet/' + idp}

    else:

        payload = {'realm': '/internet', 'spEntityID': 'urn:amazon:webservices'}



    headers = {'Content-Type': 'application/json', 'Accept-API-Version': 'resource=2.1'}



    try:

        r1 = requests.post(url, params=payload, headers=headers, verify=not test)

        if r1.status_code != 200:

            print('Received reject from OpenAM returning {} {}'.format(r1.status_code, r1.reason))

            raise

        r1j = r1.json()

        if debug:

            print('Url:         ' + r1.url)

            print('Status Code: ' + str(r1.status_code))

            print('Reason:      ' + r1.reason)

            # print('Text:        ' + r1.text

            print('Headers:     ' + str(r1.headers))

            print('Text:')

            print(json.dumps(r1j, indent=2))

    except:

        print('Request failed! ' + str(sys.exc_info()[0]))

        return None



    try:

        if forcecli:  # debugging

            raise tk.TclError

        credentials_dialog()



        print(r1j['callbacks'][0]['input'][0]['value'])

        r1j['callbacks'][0]['input'][0]['value'] = ret_credentials['userid']  # should locate 'IDToken1'

        r1j['callbacks'][1]['input'][0]['value'] = ret_credentials['token']  # should locate 'IDToken2'

        r1j['callbacks'][2]['input'][0]['value'] = ret_credentials['password']  # should locate 'IDToken3'

        if debug:

            print(json.dumps(r1j, indent=2))

    except tk.TclError:

        print('GUI unavailable, no MS-Windows or Linux X11 detected, fall back to CLI interactive')

        r1j['callbacks'][0]['input'][0]['value'] = getpass.getpass('userid')

        r1j['callbacks'][1]['input'][0]['value'] = getpass.getpass('token')

        r1j['callbacks'][2]['input'][0]['value'] = getpass.getpass('password')

    except:

        print('No valid form to fill returned! ' + str(sys.exc_info()[0]))

        return None



    try:

        r2 = requests.post(url, params=payload, headers=headers, data=json.dumps(r1j), verify=not test)

        r2j = r2.json()

        if debug:

            print('Url:        ' + r2.url)

            print('Status Code:' + str(r2.status_code))

            print('Reason:     ' + r2.reason)

            # print('Text:       ' + r2.text)

            print('Headers:    ' + str(r2.headers))

            print('Text:')

            print(json.dumps(r2j, indent=2))

    except:

        print('Authentication request failed! ' + str(sys.exc_info()[0]))

        return None



    try:

        token = r2j['tokenId']

    except:

        print('Authentication failed!')

        return None



    if debug:

        print('Extracted token: ' + token)



    if debug:  # some interesting debug code

        url = baseurl + 'json/users'

        payload = {'realm': '/internet', '_action': 'idFromSession'}

        headers = {'Content-Type': 'application/json', 'Cookie': 'es=' + token}



        try:

            r3 = requests.post(url, params=payload, headers=headers, verify=not test)

            r3j = r3.json()

            print('Url:         ' + r3.url)

            print('Status Code: ' + str(r3.status_code))

            print('Reason:      ' + r3.reason)

            # print('Text:        ' + r3.text)

            print('Headers:     ' + str(r3.headers))

            print('Text:')

            print(json.dumps(r3j, indent=2))

        except:

            print('Request failed, check network connection! ' + str(sys.exc_info()[0]))

            return None



        id = r3j['id']

        if debug:

            print('Extracted id: ' + id)



        url = baseurl + 'json/users/' + id

        payload = {'realm': '/internet'}

        headers = {'Content-Type': 'application/json', 'Cookie': 'es=' + token}



        r4 = requests.get(url, params=payload, headers=headers, verify=not test)

        r4j = r4.json()

        print('Url:         ' + r4.url)

        print('Status Code: ' + str(r4.status_code))

        print('Reason:      ' + r4.reason)

        # print('Text:        ' + r4.text)

        print('Headers:     ' + str(r4.headers))

        print(json.dumps(r4j, indent=2))



    url = baseurl + 'saml2/jsp/idpSSOInit.jsp'

    payload = {'metaAlias': '/internet/' + idp, 'spEntityID': 'urn:amazon:webservices', 'redirected': 'true'}

    headers = {'Cookie': 'es=' + token,

               # 'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',

               'Accept': 'application/xml',

               'Accept-Encoding': 'gzip, deflate, br',

               'Accept-Language': 'de,en-US;q=0.7,en;q=0.3'}



    r5 = requests.get(url, params=payload, headers=headers, verify=not test)

    if debug:

        print('Url:         ' + r5.url)

        print('Status Code: ' + str(r5.status_code))

        print('Reason:      ' + r5.reason)

        print('Text:        ' + r5.text)

        print('Headers:     ' + str(r5.headers))



    soup = BeautifulSoup(r5.text, 'html.parser')

    assertion = ''



    # Look for the SAMLResponse attribute of the input tag (determined by

    # analyzing the debug print lines above)

    for inputtag in soup.find_all('input'):

        if (inputtag.get('name') == 'SAMLResponse'):

            if debug:

                print(inputtag.get('value'))

            assertion = inputtag.get('value')



    if debug:

        print(base64.b64decode(assertion))



    # Parse the returned assertion and extract the authorized roles

    awsroles = []

    awsroles_friendly = []

    root = ET.fromstring(base64.b64decode(assertion))



    for saml2attribute in root.iter('{urn:oasis:names:tc:SAML:2.0:assertion}Attribute'):

        if (saml2attribute.get('Name') == 'https://aws.amazon.com/SAML/Attributes/Role'):

            for saml2attributevalue in saml2attribute.iter(

                    '{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue'):

                awsroles.append(saml2attributevalue.text)



    # Note the format of the attribute value should be role_arn,principal_arn

    # but lots of blogs list it as principal_arn,role_arn so let's reverse

    # them if needed.

    # Also build a user friendly display list.

    for awsrole in awsroles:

        chunks = awsrole.split(',')

        fields = chunks[0].split(':')

        account = fields[4]

        role = fields[5]

        awsroles_friendly.append(str(account) + ' '

                                 + accountFriendlyNames.get(account, accountFriendlyNames.get('undefined')).get('name')

                                 + ' '+ role.split('/')[1])

        if 'saml-provider' in chunks[0]:

            newawsrole = chunks[1] + ',' + chunks[0]

            index = awsroles.index(awsrole)

            awsroles.insert(index, newawsrole)

            awsroles.remove(awsrole)



    # If I have more than one role, ask the user which one they want,

    # otherwise just proceed

    if debug:

        print("Number of awsroles found: " + str(len(awsroles)))

        for awsrole in awsroles:

            print('List awsrole: ' + str(awsrole))

    if len(awsroles) > 1:

        try:

            if forcecli:  # debugging

                raise tk.TclError

            selection_dialog(awsroles_friendly)

        except tk.TclError:

            i = 0

            for awsrole in awsroles_friendly:

                print('awsrole#', i, awsrole)

                i += 1

            try:

                selectedroleindex = int(getpass.getpass('roleindex'))

            except:

                print('Not a valid index number')

                return None



        if debug:

            print('Using roleindex: ' + str(selectedroleindex) + ' results in ' + str(awsroles[int(selectedroleindex)]))

        role_arn = awsroles[int(selectedroleindex)].split(',')[0]

        principal_arn = awsroles[int(selectedroleindex)].split(',')[1]

    else:

        role_arn = awsroles[0].split(',')[0]

        principal_arn = awsroles[0].split(',')[1]



    if debug:

        print("Role ARN:      " + role_arn)

        print("Principal ARN: " + principal_arn)



    client = boto3.client('sts')

    assumedRoleObject = client.assume_role_with_saml(

        RoleArn=role_arn,

        PrincipalArn=principal_arn,

        SAMLAssertion=assertion

    )



    with open(auth_cache_file, 'wb') as output:

        pickle.dump(assumedRoleObject, output, pickle.HIGHEST_PROTOCOL)



    credentials = assumedRoleObject['Credentials']

    return credentials





def make_entry(parent, caption, width=None, **options):

    tk.Label(parent, text=caption).pack(side=tk.TOP)

    entry = tk.Entry(parent, **options)

    if width:

        entry.config(width=width)

    entry.pack(side=tk.TOP, padx=10, fill=tk.BOTH)

    return entry





def credentials_enter(event):

    credentials_dialog_done()





def credentials_dialog_done():

    global ret_credentials

    if debug:

        print(dlg_user.get() + ' ' + dlg_token.get() + ' ' + dlg_password.get())

    ret_credentials = {

        'userid': dlg_user.get(),

        'token': dlg_token.get(),

        'password': dlg_password.get()

    }

    dlg_root.destroy()





def credentials_dialog():

    global dlg_user

    global dlg_password

    global dlg_token

    global dlg_root



    dlg_root = tk.Tk()

    dlg_root.geometry('200x190')

    if test:

        dlg_root.title('TEST')

    else:

        dlg_root.title('PROD')

    # frame for window margin

    parent = tk.Frame(dlg_root, padx=10, pady=10)

    parent.pack(fill=tk.BOTH, expand=True)

    # entrys with not shown text

    dlg_user = make_entry(parent, "User name:", 16)

    dlg_token = make_entry(parent, "Token:", 16)

    dlg_password = make_entry(parent, "Password:", 16, show="*")

    # button to attempt to login

    b = tk.Button(parent, borderwidth=4, text="Login", width=16, pady=8, command=credentials_dialog_done)

    b.pack(side=tk.BOTTOM)

    dlg_password.bind('<Return>', credentials_enter)

    dlg_user.focus_set()

    parent.mainloop()







def selection_dialog(selections):

    def selection_dialog_done():

        global selectedroleindex

        selected = var.get()

        selectedroleindex = selected - 1

        if debug:

            print("Selection: " + str(selected) + ' at index: ' + str(selectedroleindex))

        master.destroy()

    

    def _on_mousewheel(event):

        canvas.yview_scroll(int(-1*(event.delta/120)), "units")



    def _bind_to_mousewheel(event):

        canvas.bind_all("<MouseWheel>", _on_mousewheel)



    def _unbind_from_mousewheel(event):

        canvas.unbind_all("<MouseWheel>")

    

    master = tk.Tk()

    var = tk.IntVar()

    canvas = tk.Canvas(master)

    canvas.bind('<Enter>', _bind_to_mousewheel)

    canvas.bind('<Leave>', _unbind_from_mousewheel)

    scrollbar = tk.Scrollbar(master, orient='vertical', command=canvas.yview)

    frame = tk.Frame(canvas)

    tk.Label(frame, text="Select Role").pack(anchor="w")

    # sort roles just for Mario

    alphalist = []

    for selection in selections:

        alpha = ''

        nameparts = selection.split(' ')[1:]

        for name in nameparts:

            alpha += (name+' ')

        alphalist.append(alpha[:-1])

    zipped = zip(alphalist, selections)

    selectionsorted = [x for _,x in sorted(zipped)]

    i = 1

    for selection in selectionsorted:

        tk.Radiobutton(frame, text=selection, variable=var, value=i).pack(anchor="w")

        i += 1

    tk.Button(frame, text="Continue", command=selection_dialog_done).pack(anchor="w")

    canvas.create_window(0,0,anchor='nw',window=frame)

    canvas.update_idletasks()

    canvas.configure(scrollregion=canvas.bbox('all'), yscrollcommand=scrollbar.set)

    canvas.pack(fill='both', expand=True, side='left')

    scrollbar.pack(fill='y', side='right')

    tk.mainloop()





# Iterate over credentials functions

ret_code = 1

for fun in [auth_cached, auth_live]:

    credentials = fun()



    try:

        aws_access_key_id = credentials['AccessKeyId'],

        aws_secret_access_key = credentials['SecretAccessKey']

        aws_session_token = credentials['SessionToken']

    except:

        continue



    if debug:

        print('Key ID:        ' + str(aws_access_key_id))

        print('Access Key:    ' + str(aws_secret_access_key))

        print('Session Token: ' + str(aws_session_token))

        print('Expiration:    ' + str(credentials['Expiration']))



    try:

        config = cp.ConfigParser()

        config.read(configfilename)

        if debug:

            print(config.sections())

        if 'default' not in config.sections():

            # hack to add 'default' section as it's reserved keyword in ConfigParser

            from io import StringIO



            config.readfp(StringIO('[default]'))

        config.set('default', 'aws_access_key_id', str(aws_access_key_id[0]))

        config.set('default', 'aws_secret_access_key', str(aws_secret_access_key))

        config.set('default', 'aws_session_token', str(aws_session_token))



        # make sure that config file directory is present:

        if not os.path.exists(os.path.dirname(configfilename)):

            os.makedirs(os.path.dirname(configfilename))



        # save config file

        with open(configfilename, 'w') as configfile:

            config.write(configfile)

    except:

        print(

            'Unable to store temporary credentials into: {config_file}. Other dependant interfaces will not work.'.format(

                config_file=configfilename))

        import traceback



        exc_type, exc_value, exc_traceback = sys.exc_info()

        traceback.print_exception(exc_type, exc_value, exc_traceback, limit=2, file=sys.stdout)

    try:

        s3_resource = boto3.resource(

            's3',

            config=Config(signature_version='s3v4'),

            aws_access_key_id=credentials['AccessKeyId'],

            aws_secret_access_key=credentials['SecretAccessKey'],

            aws_session_token=credentials['SessionToken'])



        ec2_resource = boto3.resource(

            'ec2',

            aws_access_key_id=credentials['AccessKeyId'],

            aws_secret_access_key=credentials['SecretAccessKey'],

            aws_session_token=credentials['SessionToken'],

            region_name='eu-central-1'

        )

    except botocore.exceptions.ClientError:

        print('Cannot connect S3 client')

        continue



    try:

        for bucket in s3_resource.buckets.all():

            print(bucket.name)

        ret_code = 0



        for instance in ec2_resource.instances.all():

            print(instance.instance_id + ' ' + instance.state['Name'])

        ret_code = 0

        break

    except:

        continue



sys.exit(ret_code)
