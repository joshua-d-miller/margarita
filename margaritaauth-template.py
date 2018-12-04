#!/usr/bin/python
'''This python script will launch Jesse Peterson's margarita
web interface for Reposado.  This modified version however will
have support for LDAP/AD authentication.  Original code by
Jesse Peterson https://github.com/jessepeterson/margarita.
Support for LDAP/AD and PyLinting by Joshua D. Miller
https://github.com/joshua-d-miller/margarita - josh@psu.edu
Last Updated Jun 29, 2017'''

import getopt
import os
import sys

from distutils.version import LooseVersion
from flask import Flask
from flask import jsonify, render_template, redirect
from flask import request, Response
from flask.ext.ldap import LDAP
from functools import wraps
from operator import itemgetter
from reposadolib import reposadocommon

try:
    import json
except ImportError:
    # couldn't find json, try simplejson library
    import simplejson as json

app = Flask(__name__)
# Uncomment and fill in the lines below with your AD/LDAP info
# app.debug = True
# ldap = LDAP(app)
# app.config['LDAP_HOST'] = 'servername.com'
# app.config['LDAP_PORT'] = '636'
# app.config['LDAP_SCHEMA'] = 'ldaps'
# app.config['LDAP_DOMAIN'] = 'domain.com'
# app.config['LDAP_SEARCH_BASE'] = 'OU=YourOUHere,DC=domain,DC=com'
# app.config['LDAP_REQUIRED_GROUP'] = (
# 'CN=Domain Admins,CN=Users,DC=domain,DC=com')
# app.secret_key = "makeyourownsecretkey"


apple_catalog_version_map = {
    # 10.14 (Snow Leopard)
    'index-10.14-10.13-10.12-10.11-10.10-10.9-mountainlion-lion'
    '-snowleopard-leopard.merged-1.sucatalog': '10.14',
    # 10.13 (High Sierra)
    'index-10.13-10.12-10.11-10.10-10.9-mountainlion-lion-snowleopard'
    '-leopard.merged-1.sucatalog': '10.13',
    # 10.12 (Sierra)
    'index-10.12-10.11-10.10-10.9-mountainlion-lion-snowleopard'
    '-leopard.merged-1.sucatalog': '10.12',
    # 10.11 (El Capitan)
    'index-10.11-10.10-10.9-mountainlion-lion-snowleopard'
    '-leopard.merged-1.sucatalog': '10.11',
    # 10.10 (Yosemite)
    'index-10.10-10.9-mountainlion-lion-snowleopard'
    '-leopard.merged-1.sucatalog': '10.10',
    # 10.9 (Mavericks)
    'index-10.9-mountainlion-lion-snowleopard'
    '-leopard.merged-1.sucatalog': '10.9',
    # 10.8 (Mountain Lion)
    'index-mountainlion-lion-snowleopard-leopard.merged-1.sucatalog': '10.8',
    # 10.7 (Lion)
    'index-lion-snowleopard-leopard.merged-1.sucatalog': '10.7',
    # 10.6 (Snow Leopard)
    'index-leopard-snowleopard.merged-1.sucatalog': '10.6',
    # 10.5 (Leopard)
    'index-leopard.merged-1.sucatalog': '10.5',
    # 10.4 (Tiger)
    'index-1.sucatalog': '10.4',
    'index.sucatalog': '10.4',
}

# Uncomment these lines when using LDAP Authentication as well
# def authenticate():
    # '''The autnthenication procedure if the user is not authenticated'''
    # return Response("Couldn't verify your credentials.  Please try again"
                    # " or contact your Systems "
                    # "Administrator.", 401, {'WWW-Authenticate':
                                            # 'Basic realm="Login required"'})


# def login_required(f):
    # '''The login_required function will prompt
    # a user for authentication if enabled'''
    # @wraps(f)
    # def decorated(*args, **kwargs):
        # auth = request.authorization
        # if not auth or not ldap.ldap_login(auth.username, auth.password):
            # return authenticate()
        # return f(*args, **kwargs)
    # return decorated

# cache the keys of the catalog version map dict
apple_catalog_suffixes = apple_catalog_version_map.keys()


def versions_from_catalogs(cats):
    '''Given an iterable of catalogs return the corresponding OS X versions'''
    versions = set()

    for cat in cats:
        # take the last portion of the catalog URL path
        short_cat = cat.split('/')[-1]
        if short_cat in apple_catalog_suffixes:
            versions.add(apple_catalog_version_map[short_cat])

    return versions


def json_response(r):
    '''Glue for wrapping raw JSON responses'''
    return Response(json.dumps(r), status=200, mimetype='application/json')


@app.route('/')
# @login_required
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
            startloc += 6  # length of <body>

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
            'size': package['Size'], })

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
                'description': get_description_content(
                    products[prodid]['description']),
                'id': prodid,
                'depr': len(products[prodid].get('AppleCatalogs', [])) < 1,
                'branches': [],
                'oscatalogs': sorted(
                    versions_from_catalogs(products[prodid].get(
                        'OriginalAppleCatalogs')),
                    key=LooseVersion, reverse=True),
                'packages': product_urls(products[prodid]['CatalogEntry']), }

            for branch in catalog_branches.keys():
                if prodid in catalog_branches[branch]:
                    prod['branches'].append(branch)

            prodlist.append(prod)
        else:
            print 'Invalid update!'

    sprodlist = sorted(prodlist, key=itemgetter('PostDate'), reverse=True)

    return json_response({
        'products': sprodlist, 'branches': catalog_branches.keys()})


@app.route('/new_branch/<branchname>', methods=['POST'])
# @login_required
def new_branch(branchname):
    catalog_branches = reposadocommon.getCatalogBranches()
    if branchname in catalog_branches:
        reposadocommon.print_stderr('Branch %s already exists!', branchname)
        abort(401)
    catalog_branches[branchname] = []
    reposadocommon.writeCatalogBranches(catalog_branches)

    return jsonify(result='success')


@app.route('/delete_branch/<branchname>', methods=['POST'])
# @login_required
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

    return jsonify(result=True)


@app.route('/add_all/<branchname>', methods=['POST'])
# @login_required
def add_all(branchname):
    products = reposadocommon.getProductInfo()
    catalog_branches = reposadocommon.getCatalogBranches()

    catalog_branches[branchname] = products.keys()

    reposadocommon.writeCatalogBranches(catalog_branches)
    reposadocommon.writeAllBranchCatalogs()

    return jsonify(result=True)


@app.route('/process_queue', methods=['POST'])
# @login_required
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
# @login_required
def dup_apple(branchname):
    catalog_branches = reposadocommon.getCatalogBranches()

    if branchname not in catalog_branches.keys():
        print 'No branch ' + branchname
        return jsonify(result=False)

    # generate list of (non-deprecated) updates
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
# @login_required
def dup(frombranch, tobranch):
    catalog_branches = reposadocommon.getCatalogBranches()

    if frombranch not in catalog_branches.keys() or \
       tobranch not in catalog_branches.keys():
        print 'No branch ' + branchname
        return jsonify(result=False)

    catalog_branches[tobranch] = catalog_branches[frombranch]

    print 'Writing catalogs'
    reposadocommon.writeCatalogBranches(catalog_branches)
    reposadocommon.writeAllBranchCatalogs()

    return jsonify(result=True)


@app.route('/config_data', methods=['POST'])
def config_data():
    # catalog_branches = reposadocommon.getCatalogBranches()
    check_prods = request.json

    if len(check_prods) > 0:
        cd_prods = reposadocommon.check_or_remove_config_data_attribute(
            check_prods, suppress_output=True)
    else:
        cd_prods = []

    response_prods = {}
    for prod_id in check_prods:
        response_prods.update(
            {prod_id: True if prod_id in cd_prods else False})

    print response_prods

    return json_response(response_prods)


@app.route('/remove_config_data/<product>', methods=['POST'])
def remove_config_data(product):
    # catalog_branches = reposadocommon.getCatalogBranches()
    check_prods = request.json

    products = reposadocommon.check_or_remove_config_data_attribute(
        [product, ], remove_attr=True, suppress_output=True)

    return json_response(products)


if __name__ == '__main__':
    app.run('0.0.0.0', debug=True, port=4755,
            ssl_context=('YourCertPEM',
                         'YourCertKey'))