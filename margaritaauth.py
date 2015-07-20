#!/usr/env python
'''This python script will launch Jesse Peterson's margarita
web interface for Reposado.  This modified version however will
have support for LDAP/AD authentication.  Original code by
Jesse Peterson https://github.com/jessepeterson/margarita.
Support for LDAP/AD and PyLinting by Joshua D. Miller
https://github.com/joshua-d-miller/margarita - josh@psu.edu
Last Updated July 20, 2015'''

from flask import Flask
from flask import jsonify, render_template, redirect
from flask import request, Response
# Uncomment the following line to use LDAP
#from flask.ext.ldap import LDAP
app = Flask(__name__)
# Uncomment and fill in the lines below with your AD/LDAP info
#app.debug = True
#ldap = LDAP(app)
#app.config['LDAP_HOST'] = 'servername.com'
#app.config['LDAP_PORT'] = '636'
#app.config['LDAP_SCHEMA'] = 'ldaps'
#app.config['LDAP_DOMAIN'] = 'domain.com'
#app.config['LDAP_SEARCH_BASE'] = 'OU=YourOUHere,DC=domain,DC=com'
#app.config['LDAP_REQUIRED_GROUP'] = 'CN=Domain Admins,CN=Users,DC=domain,DC=com'
#app.secret_key = "makeyourownsecretkey"

import os, sys
try:
    import json
except ImportError:
	# couldn't find json, try simplejson library
    import simplejson as json
import getopt
from operator import itemgetter
from distutils.version import LooseVersion

from reposadolib import reposadocommon
#from functools import wraps

APPLE_CATALOG_VERSION_MAP = {
    'index-10.11-10.10-10.9-mountainlion-lion-snowleopard-leopard.merged-1.sucatalog': '10.11',
    'index-10.10-10.9-mountainlion-lion-snowleopard-leopard.merged-1.sucatalog': '10.10',
    'index-10.9-mountainlion-lion-snowleopard-leopard.merged-1.sucatalog': '10.9',
    'index-mountainlion-lion-snowleopard-leopard.merged-1.sucatalog': '10.8',
    'index-lion-snowleopard-leopard.merged-1.sucatalog': '10.7',
    'index-leopard-snowleopard.merged-1.sucatalog': '10.6',
    'index-leopard.merged-1.sucatalog': '10.5',
    'index-1.sucatalog': '10.4',
    'index.sucatalog': '10.4',
}

#def authenticate():
    #'''The autnthenication procedure if the user is not authenticated'''
    #return Response("Couldn't verify your credentials.  Please try again \
    #or contact your Systems Administrator.", 401, {'WWW-Authenticate': \
    #'Basic realm="Login required"'})

#def login_required(f):
	#'''The login_required function will prompt a user for authentication if enabled'''
    #@wraps(f)
	#def decorated(*args, **kwargs):
		#auth = request.authorization
		#if not auth or not ldap.ldap_login(auth.username, auth.password):
			#return authenticate()
		#return f(*args, **kwargs)
	#return decorated

# cache the keys of the catalog version map dict
APPLE_CATALOG_SUFFIXES = APPLE_CATALOG_VERSION_MAP.keys()

def versions_from_catalogs(cats):
    '''Given an iterable of catalogs return the corresponding OS X versions'''
    versions = set()

    for cat in cats:
		# take the last portion of the catalog URL path
        short_cat = cat.split('/')[-1]
        if short_cat in APPLE_CATALOG_SUFFIXES:
            versions.add(APPLE_CATALOG_VERSION_MAP[short_cat])

    return versions

def json_response(r):
    '''Glue for wrapping raw JSON responses'''
    return Response(json.dumps(r), status=200, mimetype='application/json')

@app.route('/')
#@login_required
def index():
    return render_template('margarita.html')

@app.route('/branches', methods=['GET'])
def list_branches():
    '''Returns catalog branch names and associated updates'''
    catalog_branches = reposadocommon.getCatalogBranches()

    return json_response(catalog_branches.keys())

def get_description_content(html):
    if len(html) == 0:
        return None

	# in the interest of (attempted) speed, try to avoid regexps
    lwrhtml = html.lower()

    celem = 'p'
    startloc = lwrhtml.find('<' + celem + '>')

    if startloc == -1:
        startloc = lwrhtml.find('<' + celem + ' ')

    if startloc == -1:
        celem = 'body'
        startloc = lwrhtml.find('<' + celem)

        if startloc != -1:
            startloc += 6 # length of <body>

    if startloc == -1:
		# no <p> nor <body> tags. bail.
        return None

    endloc = lwrhtml.rfind('</' + celem + '>')

    if endloc == -1:
        endloc = len(html)
    elif celem != 'body':
		# if the element is a body tag, then don't include it.
		# DOM parsing will just ignore it anyway
        endloc += len(celem) + 3

    return html[startloc:endloc]

def product_urls(cat_entry):
    '''Retreive package URLs for a given reposado product CatalogEntry.

	Will rewrite URLs to be served from local reposado repo if necessary.'''

    packages = cat_entry.get('Packages', [])

    pkg_urls = []
    for package in packages:
        pkg_urls.append({
            'url': reposadocommon.rewriteOneURL(package['URL']),
            'size': package['Size'],
            })

    return pkg_urls

@app.route('/products', methods=['GET'])
def products():
    products = reposadocommon.getProductInfo()
    catalog_branches = reposadocommon.getCatalogBranches()

    prodlist = []
    for prodid in products.keys():
        if 'title' in products[prodid] and 'version' in products[prodid] \
        and 'PostDate' in products[prodid]:
            prod = {
                'title': products[prodid]['title'],
                'version': products[prodid]['version'],
                'PostDate': products[prodid]['PostDate'].strftime('%Y-%m-%d'),
                'description': get_description_content(products[prodid]['description']),
                'id': prodid,
                'depr': len(products[prodid].get('AppleCatalogs', [])) < 1,
                'branches': [],
                'oscatalogs': sorted(versions_from_catalogs \
                	(products[prodid].get('OriginalAppleCatalogs')), key=LooseVersion, reverse=True),
                'packages': product_urls(products[prodid]['CatalogEntry']),
                }

            for branch in catalog_branches.keys():
                if prodid in catalog_branches[branch]:
                    prod['branches'].append(branch)

            prodlist.append(prod)
        else:
            print 'Invalid update!'

    sprodlist = sorted(prodlist, key=itemgetter('PostDate'), reverse=True)

    return json_response({'products': sprodlist, 'branches': catalog_branches.keys()})

@app.route('/new_branch/<branchname>', methods=['POST'])
#@login_required
def new_branch(branchname):
    catalog_branches = reposadocommon.getCatalogBranches()
    if branchname in catalog_branches:
        reposadocommon.print_stderr('Branch %s already exists!', branchname)
        abort(401)
    catalog_branches[branchname] = []
    reposadocommon.writeCatalogBranches(catalog_branches)
    
    return jsonify(result='success')

@app.route('/delete_branch/<branchname>', methods=['POST'])
#@login_required
def delete_branch(branchname):
    catalog_branches = reposadocommon.getCatalogBranches()
    if not branchname in catalog_branches:
        reposadocommon.print_stderr('Branch %s does not exist!', branchname)
        return

    del catalog_branches[branchname]

    # this is not in the common library, so we have to duplicate code
    # from repoutil
    for catalog_URL in reposadocommon.pref('AppleCatalogURLs'):
        localcatalogpath = reposadocommon.getLocalPathNameFromURL(catalog_URL)
        # now strip the '.sucatalog' bit from the name
        if localcatalogpath.endswith('.sucatalog'):
            localcatalogpath = localcatalogpath[0:-10]
        branchcatalogpath = localcatalogpath + '_' + branchname + '.sucatalog'
        if os.path.exists(branchcatalogpath):
            reposadocommon.print_stdout(
                'Removing %s', os.path.basename(branchcatalogpath))
            os.remove(branchcatalogpath)

    reposadocommon.writeCatalogBranches(catalog_branches)
    
    return jsonify(result=True);

@app.route('/add_all/<branchname>', methods=['POST'])
#@login_required
def add_all(branchname):
    products = reposadocommon.getProductInfo()
    catalog_branches = reposadocommon.getCatalogBranches()

    catalog_branches[branchname] = products.keys()

    reposadocommon.writeCatalogBranches(catalog_branches)
    reposadocommon.writeAllBranchCatalogs()

    return jsonify(result=True)


@app.route('/process_queue', methods=['POST'])
#@login_required
def process_queue():
    catalog_branches = reposadocommon.getCatalogBranches()

    for change in request.json:
        prodId = change['productId']
        branch = change['branch']

        if branch not in catalog_branches.keys():
            print 'No such catalog'
            continue

        if change['listed']:
			# if this change /was/ listed, then unlist it
            if prodId in catalog_branches[branch]:
                print 'Removing product %s from branch %s' % (prodId, branch, )
                catalog_branches[branch].remove(prodId)
        else:
			# if this change /was not/ listed, then list it
            if prodId not in catalog_branches[branch]:
                print 'Adding product %s to branch %s' % (prodId, branch, )
                catalog_branches[branch].append(prodId)

    print 'Writing catalogs'
    reposadocommon.writeCatalogBranches(catalog_branches)
    reposadocommon.writeAllBranchCatalogs()

    return jsonify(result=True)

@app.route('/dup_apple/<branchname>', methods=['POST'])
#@login_required
def dup_apple(branchname):
    catalog_branches = reposadocommon.getCatalogBranches()

    if branchname not in catalog_branches.keys():
        print 'No branch ' + branchname
        return jsonify(result=False)

	# generate list of (non-drepcated) updates
    products = reposadocommon.getProductInfo()
    prodlist = []
    for prodid in products.keys():
        if len(products[prodid].get('AppleCatalogs', [])) >= 1:
            prodlist.append(prodid)

    catalog_branches[branchname] = prodlist

    print 'Writing catalogs'
    reposadocommon.writeCatalogBranches(catalog_branches)
    reposadocommon.writeAllBranchCatalogs()

    return jsonify(result=True)

@app.route('/dup/<frombranch>/<tobranch>', methods=['POST'])
#@login_required
def dup(frombranch, tobranch):
    catalog_branches = reposadocommon.getCatalogBranches()

    if frombranch not in catalog_branches.keys() or tobranch not in catalog_branches.keys():
        print 'No branch ' + branchname
        return jsonify(result=False)

    catalog_branches[tobranch] = catalog_branches[frombranch]

    print 'Writing catalogs'
    reposadocommon.writeCatalogBranches(catalog_branches)
    reposadocommon.writeAllBranchCatalogs()

    return jsonify(result=True)

if __name__ == '__main__':
    app.run('0.0.0.0', debug=True, port=4755, \
        ssl_context=('YourCertFile', 'YourCertKeyFile'))
