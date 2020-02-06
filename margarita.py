#!/usr/bin/env python
# pylint:disable=E0401, E0611, C0103, W0621, W0612
# pylint:disable=R0912, R0914, R0915
'''Margarita - An Flask Application for managing
Reposado Catalogs'''
# This Flask application will only work with
# Python 3 - Tested with Python 3.6.8 on CentOS 8
# Original Project by jessepeterson
# https://github.com/jessepterson/margarita
# Joshua D. Miller - josh@psu.edu
# The Pennsylvania State University
# Last Updated February 5, 2020

# Imports Needed
from __future__ import print_function
from urllib.parse import urlparse
from distutils.version import LooseVersion
from operator import itemgetter
import getopt
import os
import sys
from flask import (Flask, jsonify, request, render_template,
                   redirect, session, Response, make_response)
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.utils import OneLogin_Saml2_Utils
from secret_key import SECRET_KEY
# Reposado library which you will need to make
# a symbolic link to in your margarita directory
from reposadolib import reposadocommon

try:
    import json
except ImportError:
	# couldn't find json, try simplejson library
    import simplejson as json


# Configure the Application
app = Flask(__name__)

app.config['SECRET_KEY'] = SECRET_KEY
app.config['SAML_PATH'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'saml')


apple_catalog_version_map = {
    # Catalina
    'index-10.15-10.14-10.13-10.12-10.11-10.10-10.9'
    '-mountainlion-lion-snowleopard-leopard.merged-1.sucatalog': '10.15',
    # Mojave
    'index-10.14-10.13-10.12-10.11-10.10-10.9'
    '-mountainlion-lion-snowleopard-leopard.merged-1.sucatalog': '10.14',
    # High Sierra
    'index-10.13-10.12-10.11-10.10-10.9-mountainlion'
    '-lion-snowleopard-leopard.merged-1.sucatalog': '10.13',
    # Sierra
    'index-10.12-10.11-10.10-10.9-mountainlion'
    '-lion-snowleopard-leopard.merged-1.sucatalog': '10.12',
    # El Capitan
    'index-10.11-10.10-10.9-mountainlion-lion-'
    'snowleopard-leopard.merged-1.sucatalog': '10.11',
    # Yosemite
    'index-10.10-10.9-mountainlion-lion-snowleopard'
    '-leopard.merged-1.sucatalog': '10.10',
    # Mavericks
    'index-10.9-mountainlion-lion-snowleopard'
    '-leopard.merged-1.sucatalog': '10.9',
    # Mountain Lion
    'index-mountainlion-lion-snowleopard-'
    'leopard.merged-1.sucatalog': '10.8',
    # Lion
    'index-lion-snowleopard-leopard.merged-1.sucatalog': '10.7',
    # Snow Leopard
    'index-leopard-snowleopard.merged-1.sucatalog': '10.6',
    # Leopard
    'index-leopard.merged-1.sucatalog': '10.5',
    # Tiger
    'index-1.sucatalog': '10.4',
	   'index.sucatalog': '10.4',
}

# cache the keys of the catalog version map dict
apple_catalog_suffixes = apple_catalog_version_map.keys()

def init_saml_auth(req):
    '''Attaches the SAML_PATH settings to Python SAML'''
    auth = OneLogin_Saml2_Auth(req, custom_base_path=app.config['SAML_PATH'])
    return auth


def prepare_flask_request(request):
    '''Sets up the flask request
    Reference https://github.com/onelogin/python-saml
    /tree/master/demo-flask/templates'''

    # If server is behind proxys or balancers use the HTTP_X_FORWARDED fields
    url_data = urlparse(request.url)
    return {
        'https': 'on' if request.scheme == 'https' else 'off',
        'http_host': request.host,
        'server_port': url_data.port,
        'script_name': request.path,
        'get_data': request.args.copy(),
        'post_data': request.form.copy(),
        # Uncomment if using ADFS as IdP, https://github.com/onelogin/python-saml/pull/144
        # 'lowercase_urlencoding': True,
        'query_string': request.query_string
    }


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


@app.route('/', methods=['GET', 'POST'])
def index():
    '''Function to ask for SAML Authentication and then
    display the Margarita login page'''
    req = prepare_flask_request(request)
    auth = init_saml_auth(req)
    errors = []
    error_reason = None
    not_auth_warn = False
    success_slo = False
    attributes = False
    paint_logout = False

    if 'sso' in request.args:
        print('Authenticating....')
        return redirect(auth.login())
        # If AuthNRequest ID need to be stored in order to later validate it, do instead
        # sso_built_url = auth.login()
        # request.session['AuthNRequestID'] = auth.get_last_request_id()
        # return redirect(sso_built_url)
    elif 'sso2' in request.args:
        return_to = '%sattrs/' % request.host_url
        return redirect(auth.login(return_to))
    elif 'slo' in request.args:
        name_id = session_index = name_id_format = name_id_nq = name_id_spnq = None
        if 'samlNameId' in session:
            name_id = session['samlNameId']
        if 'samlSessionIndex' in session:
            session_index = session['samlSessionIndex']
        if 'samlNameIdFormat' in session:
            name_id_format = session['samlNameIdFormat']
        if 'samlNameIdNameQualifier' in session:
            name_id_nq = session['samlNameIdNameQualifier']
        if 'samlNameIdSPNameQualifier' in session:
            name_id_spnq = session['samlNameIdSPNameQualifier']

        return redirect(auth.logout(
            name_id=name_id, session_index=session_index, nq=name_id_nq,
            name_id_format=name_id_format, spnq=name_id_spnq))
        #  If LogoutRequest ID need to be stored in order to later validate it, do instead
        #  slo_built_url = auth.logout(name_id=name_id, session_index=session_index)
        #  session['LogoutRequestID'] = auth.get_last_request_id()
        # return redirect(slo_built_url)
    elif 'acs' in request.args:
        request_id = None
        if 'AuthNRequestID' in session:
            request_id = session['AuthNRequestID']

        auth.process_response(request_id=request_id)
        errors = auth.get_errors()
        not_auth_warn = not auth.is_authenticated()
        if len(errors) == 0:
            if 'AuthNRequestID' in session:
                del session['AuthNRequestID']
            session['samlUserdata'] = auth.get_attributes()
            session['samlNameIdFormat'] = auth.get_nameid_format()
            session['samlNameIdNameQualifier'] = auth.get_nameid_nq()
            session['samlNameIdSPNameQualifier'] = auth.get_nameid_spnq()
            session['samlSessionIndex'] = auth.get_session_index()
            self_url = OneLogin_Saml2_Utils.get_self_url(req)
            if 'RelayState' in request.form and self_url != request.form['RelayState']:
                return redirect(auth.redirect_to(request.form['RelayState']))
        elif auth.get_settings().is_debug_active():
            error_reason = auth.get_last_error_reason()
    elif 'sls' in request.args:
        request_id = None
        if 'LogoutRequestID' in session:
            request_id = session['LogoutRequestID']
        dscb = lambda: session.clear()
        url = auth.process_slo(request_id=request_id, delete_session_cb=dscb)
        errors = auth.get_errors()
        if len(errors) == 0:
            if url is not None:
                return redirect(url)
            else:
                success_slo = True
        elif auth.get_settings().is_debug_active():
            error_reason = auth.get_last_error_reason()

    if 'samlUserdata' in session:
        paint_logout = True
        if len(session['samlUserdata']) > 0:
            attributes = session['samlUserdata'].items()

    return render_template(
        'margarita.html',
        errors=errors,
        error_reason=error_reason,
        not_auth_warn=not_auth_warn,
        success_slo=success_slo,
        attributes=attributes,
        paint_logout=paint_logout
    )

@app.route('/metadata/')
def metadata():
    '''Get the metadata for your IDP after
    you have configured your settings.json
    and advanced_settings.json in your
    saml directory'''
    req = prepare_flask_request(request)
    auth = init_saml_auth(req)
    settings = auth.get_settings()
    metadata = settings.get_sp_metadata()
    errors = settings.validate_metadata(metadata)

    if len(errors) == 0:
        resp = make_response(metadata, 200)
        resp.headers['Content-Type'] = 'text/xml'
    else:
        resp = make_response(', '.join(errors), 500)
    return resp


@app.route('/branches', methods=['GET'])
def list_branches():
    '''Returns catalog branch names and associated updates'''
    catalog_branches = reposadocommon.get_catalog_branches()

    return json_response(catalog_branches.keys())

def get_description_content(html):
    '''Gets the content descriptions of items'''
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
        pkg_urls.append(
            {'url': reposadocommon.rewrite_one_url(
                package['URL']), 'size': package['Size'],})

    return pkg_urls

@app.route('/products', methods=['GET'])
def products():
    '''Get all products available currently whether
    listed or unlisted from reposado'''
    products = reposadocommon.get_product_info()
    catalog_branches = reposadocommon.get_catalog_branches()

    prodlist = []
    for prodid in products.keys():
        if ('title' in products[prodid] and 'version' in products[prodid]
                and 'PostDate' in products[prodid]):
            prod = {
				            'title': products[prodid]['title'],
				            'version': products[prodid]['version'],
				            'PostDate': products[prodid]['PostDate'].strftime(
                                                '%Y-%m-%d'),
				            'description': get_description_content(
                                                products[prodid]['description']),
				            'id': prodid,
				            'depr': len(
                                                products[prodid].get(
                                                    'AppleCatalogs', [])) < 1,
				            'branches': [],
				            'oscatalogs': sorted(versions_from_catalogs(
                                                products[prodid].get(
                                                    'OriginalAppleCatalogs')),
                                     key=LooseVersion,
                                     reverse=True),
				            'packages': product_urls(
                                                products[prodid]['CatalogEntry']),
				        }

            for branch in catalog_branches.keys():
                if prodid in catalog_branches[branch]:
                    prod['branches'].append(branch)

            prodlist.append(prod)
        else:
            print('Invalid update!')

    sprodlist = sorted(prodlist, key=itemgetter('PostDate'), reverse=True)

    return json_response({'products': sprodlist, 'branches': list(catalog_branches.keys())})

@app.route('/new_branch/<branchname>', methods=['POST'])
def new_branch(branchname):
    '''Create a new branch in reposado'''
    catalog_branches = reposadocommon.get_catalog_branches()
    if branchname in catalog_branches:
        reposadocommon.print_stderr('Branch %s already exists!', branchname)
        abort(401)
    catalog_branches[branchname] = []
    reposadocommon.write_catalog_branches(catalog_branches)

    return jsonify(result='success')

@app.route('/delete_branch/<branchname>', methods=['POST'])
def delete_branch(branchname):
    '''Delete a branch in reposado'''
    catalog_branches = reposadocommon.get_catalog_branches()
    if not branchname in catalog_branches:
        reposadocommon.print_stderr('Branch %s does not exist!', branchname)
        return

    del catalog_branches[branchname]

    # this is not in the common library, so we have to duplicate code
    # from repoutil
    for catalog_URL in reposadocommon.pref('AppleCatalogURLs'):
        localcatalogpath = reposadocommon.get_local_pathname_from_url(catalog_URL)
        # now strip the '.sucatalog' bit from the name
        if localcatalogpath.endswith('.sucatalog'):
            localcatalogpath = localcatalogpath[0:-10]
        branchcatalogpath = localcatalogpath + '_' + branchname + '.sucatalog'
        if os.path.exists(branchcatalogpath):
            reposadocommon.print_stdout(
                'Removing %s', os.path.basename(branchcatalogpath))
            os.remove(branchcatalogpath)

    reposadocommon.write_catalog_branches(catalog_branches)

    return jsonify(result=True)

@app.route('/add_all/<branchname>', methods=['POST'])
def add_all(branchname):
    '''Add all products to branch in reposado'''
    products = reposadocommon.get_product_info()
    catalog_branches = reposadocommon.get_catalog_branches()

    catalog_branches[branchname] = products.keys()

    reposadocommon.write_catalog_branches(catalog_branches)
    reposadocommon.write_all_branch_catalogs()

    return jsonify(result=True)


@app.route('/process_queue', methods=['POST'])
def process_queue():
    catalog_branches = reposadocommon.get_catalog_branches()

    for change in request.json:
        prodId = change['productId']
        branch = change['branch']

        if branch not in catalog_branches.keys():
            print('No such catalog')
            continue

        if change['listed']:
            # if this change /was/ listed, then unlist it
            if prodId in catalog_branches[branch]:
                print('Removing product %s from branch %s' % (prodId, branch, ))
                catalog_branches[branch].remove(prodId)
        else:
			# if this change /was not/ listed, then list it
            if prodId not in catalog_branches[branch]:
                print('Adding product %s to branch %s' % (prodId, branch, ))
                catalog_branches[branch].append(prodId)

    print('Writing catalogs')
    reposadocommon.write_catalog_branches(catalog_branches)
    reposadocommon.write_all_branch_catalogs()

    return jsonify(result=True)

@app.route('/dup_apple/<branchname>', methods=['POST'])
def dup_apple(branchname):
    '''Duplicate apple branch in reposado to one of your branches'''
    catalog_branches = reposadocommon.get_catalog_branches()

    if branchname not in catalog_branches.keys():
        print('No branch ' + branchname)
        return jsonify(result=False)

	# generate list of (non-deprecated) updates
    products = reposadocommon.get_product_info()
    prodlist = []
    for prodid in products.keys():
        if len(products[prodid].get('AppleCatalogs', [])) >= 1:
            prodlist.append(prodid)

    catalog_branches[branchname] = prodlist

    print('Writing catalogs')
    reposadocommon.write_catalog_branches(catalog_branches)
    reposadocommon.write_all_branch_catalogs()

    return jsonify(result=True)

@app.route('/dup/<frombranch>/<tobranch>', methods=['POST'])
def dup(frombranch, tobranch):
    '''Duplicate one of your branches to another'''
    catalog_branches = reposadocommon.get_catalog_branches()

    if frombranch not in catalog_branches.keys() or tobranch not in catalog_branches.keys():
        print('No branch ' + branchname)
        return jsonify(result=False)

    catalog_branches[tobranch] = catalog_branches[frombranch]

    print('Writing catalogs')
    reposadocommon.write_catalog_branches(catalog_branches)
    reposadocommon.write_all_branch_catalogs()

    return jsonify(result=True)

@app.route('/config_data', methods=['POST'])
def config_data():
    '''Get current configuration from reposado'''
	# catalog_branches = reposadocommon.getCatalogBranches()
    check_prods = request.json

    if len(check_prods) > 0:
        cd_prods = reposadocommon.check_or_remove_config_data_attr(
            check_prods, suppress_output=True)
    else:
        cd_prods = []

    response_prods = {}
    for prod_id in check_prods:
        response_prods.update({prod_id: True if prod_id in cd_prods else False})

    print(response_prods)

    return json_response(response_prods)

@app.route('/remove_config_data/<product>', methods=['POST'])
def remove_config_data(product):
    '''Remove configuration data'''
	# catalog_branches = reposadocommon.getCatalogBranches()
    check_prods = request.json

    products = reposadocommon.check_or_remove_config_data_attr(
        [product, ], remove_attr=True, suppress_output=True)

    return json_response(products)

def main():
    '''main function that runs Margarita as a WSGI
    Web Application'''
    optlist, args = getopt.getopt(sys.argv[1:], 'db:p:')

    flaskargs = {}
    flaskargs['host'] = '0.0.0.0'
    flaskargs['port'] = 8089
    flaskargs['threaded'] = True

    for o, a in optlist:
        if o == '-d':
            flaskargs['debug'] = True
        elif o == '-b':
            flaskargs['host'] = a
        elif o == '-p':
            flaskargs['port'] = int(a)

    app.run(**flaskargs)

if __name__ == '__main__':
    main()
