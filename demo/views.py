from django.conf import settings
from django.urls import reverse
from django.http import (HttpResponse, HttpResponseRedirect,
                         HttpResponseServerError)
from django.shortcuts import render

from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.settings import OneLogin_Saml2_Settings
from onelogin.saml2.utils import OneLogin_Saml2_Utils


def get_sp_id_info():
    with open('cert.pem', mode='rt', encoding='utf-8') as cert_file:
        sp_cert = cert_file.read()

    with open('key.pem', mode='rt', encoding='utf-8') as key_file:
        sp_key = key_file.read()

    return (sp_key, sp_cert)

def get_idp_id_info():
    return "-----BEGIN CERTIFICATE----- MIIErDCCA5SgAwIBAgIOAX4n3NOVAAAAAHxNAncwDQYJKoZIhvcNAQELBQAwgZAx\n KDAmBgNVBAMMH1NlbGZTaWduZWRDZXJ0XzA1SmFuMjAyMl8wMTMxMzAxGDAWBgNV\n BAsMDzAwRDVmMDAwMDA2UDZIbzEXMBUGA1UECgwOU2FsZXNmb3JjZS5jb20xFjAU\n BgNVBAcMDVNhbiBGcmFuY2lzY28xCzAJBgNVBAgMAkNBMQwwCgYDVQQGEwNVU0Ew\n HhcNMjIwMTA1MDEzMTMwWhcNMjMwMTA1MDAwMDAwWjCBkDEoMCYGA1UEAwwfU2Vs\n ZlNpZ25lZENlcnRfMDVKYW4yMDIyXzAxMzEzMDEYMBYGA1UECwwPMDBENWYwMDAw\n MDZQNkhvMRcwFQYDVQQKDA5TYWxlc2ZvcmNlLmNvbTEWMBQGA1UEBwwNU2FuIEZy\n YW5jaXNjbzELMAkGA1UECAwCQ0ExDDAKBgNVBAYTA1VTQTCCASIwDQYJKoZIhvcN\n AQEBBQADggEPADCCAQoCggEBAKV+1BeyXYtN/pPTXwEvcEmYwFBESVcGdQxo7Btg\n npLwYuI2LUf/Q4t9y5s936GUSNdvdCKom8tf98/rX2J54D570S//m7XD5h3O7jLi\n RUnmcgPc2hKFMjlvtjEv/Us35QXsfVoIIZIzUYO9JrBzQPllp2biqSWrSZPNfuQB\n iK7i/PPSwGxw3KEXtuWVRQ48ZYmYPOxIYh7i+syISmiSQHoAEsLbjfAcwfFymIrV\n C1FI87Xlsi+ND6/1imH84zgzfrHYa1kVXMrxwqGihxoVIJi5r5Qnqas+nyrdvm/v\n k+wcekCwWNQm/o1nu5jjoQp3G+3diCI72FpsCzxUUIFGjpcCAwEAAaOCAQAwgf0w\n HQYDVR0OBBYEFIo3WzHySPzoQRiBwc0YPm+Fc33AMA8GA1UdEwEB/wQFMAMBAf8w\n gcoGA1UdIwSBwjCBv4AUijdbMfJI/OhBGIHBzRg+b4VzfcChgZakgZMwgZAxKDAm\n BgNVBAMMH1NlbGZTaWduZWRDZXJ0XzA1SmFuMjAyMl8wMTMxMzAxGDAWBgNVBAsM\n DzAwRDVmMDAwMDA2UDZIbzEXMBUGA1UECgwOU2FsZXNmb3JjZS5jb20xFjAUBgNV\n BAcMDVNhbiBGcmFuY2lzY28xCzAJBgNVBAgMAkNBMQwwCgYDVQQGEwNVU0GCDgF+\n J9zTlQAAAAB8TQJ3MA0GCSqGSIb3DQEBCwUAA4IBAQB5losN70wjywCJOHiEA1F3\n Rd8Z+s/5xKB1jIH6x8MLS0p8orKeK9tkjFi4Lwg+FjAArXfvyVoLfxVlxKP3q+v+\n kbshuI6mU+5CHFNzzaQrxaFxsHu8rpbs2sNWMx48MnnTTkoTqF3y9W/vlqqsvD+n\n Rbg6a0tPFu9GO5NmX5y+cO0p1v3l7Npu5LuDvjtpIXYZmngwntnp1P4VpLCZYH5F\n EZ1hDCchlWXmZ6gzpcGcXP9m/PyfTbqSdU91d4LLEzUlhcxrVAWNmvcWn5S+WZ5a\n s1eExNftOfYIZruDh51y6M+9WuYNuMVsnRaeMbHlcdtojsyiMOHopWvI4n8d/ijl\n -----END CERTIFICATE-----"

def get_saml_settings(sp_key, sp_cert, idp_cert):
    return {
    "strict": True,
    "debug": True,
    "sp": {
        "entityId": "https://localhost:8000/metadata/",
        "assertionConsumerService": {
            "url": "https://localhost:8000/?acs",
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        },
        "singleLogoutService": {
            "url": "https://localhost:8000/sls/",
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        },
        "NameIDFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
        "x509cert": sp_cert,
        "privateKey": sp_key
    },
    "idp": {
        "entityId": "https://patri-dev-ed.my.salesforce.com",
        "singleSignOnService": {
            "url": "https://patri-dev-ed.my.salesforce.com/idp/endpoint/HttpRedirect",
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        },
        "singleLogoutService": {
            "url": "https://patri-dev-ed.my.salesforce.com/services/auth/idp/saml2/logout",
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        },
        "x509cert": idp_cert
    }
}

def init_saml_auth(req):
    (sp_key, sp_cert) = get_sp_id_info()
    idp_cert = get_idp_id_info()
    saml_settings = get_saml_settings(sp_key, sp_cert, idp_cert)

    auth = OneLogin_Saml2_Auth(req, saml_settings)
    return auth

def prepare_django_request(request):
    # If server is behind proxys or balancers use the HTTP_X_FORWARDED fields
    result = {
        'https': 'on' if request.is_secure() else 'off',
        'http_host': request.META['HTTP_HOST'],
        'script_name': request.META['PATH_INFO'],
        'get_data': request.GET.copy(),
        # Uncomment if using ADFS as IdP, https://github.com/onelogin/python-saml/pull/144
        # 'lowercase_urlencoding': True,
        'post_data': request.POST.copy()
    }
    return result

def index(request):
    req = prepare_django_request(request)
    auth = init_saml_auth(req)
    errors = []
    error_reason = None
    not_auth_warn = False
    success_slo = False
    attributes = False
    paint_logout = False

    if 'sso' in req['get_data']:
        return HttpResponseRedirect(auth.login())
        # If AuthNRequest ID need to be stored in order to later validate it, do instead
        # sso_built_url = auth.login()
        # request.session['AuthNRequestID'] = auth.get_last_request_id()
        # return HttpResponseRedirect(sso_built_url)
    elif 'sso2' in req['get_data']:
        return_to = OneLogin_Saml2_Utils.get_self_url(req) + reverse('attrs')
        return HttpResponseRedirect(auth.login(return_to))
    elif 'slo' in req['get_data']:
        name_id = session_index = name_id_format = name_id_nq = name_id_spnq = None
        if 'samlNameId' in request.session:
            name_id = request.session['samlNameId']
        if 'samlSessionIndex' in request.session:
            session_index = request.session['samlSessionIndex']
        if 'samlNameIdFormat' in request.session:
            name_id_format = request.session['samlNameIdFormat']
        if 'samlNameIdNameQualifier' in request.session:
            name_id_nq = request.session['samlNameIdNameQualifier']
        if 'samlNameIdSPNameQualifier' in request.session:
            name_id_spnq = request.session['samlNameIdSPNameQualifier']

        return HttpResponseRedirect(auth.logout(name_id=name_id, session_index=session_index, nq=name_id_nq, name_id_format=name_id_format, spnq=name_id_spnq))
        # If LogoutRequest ID need to be stored in order to later validate it, do instead
        # slo_built_url = auth.logout(name_id=name_id, session_index=session_index)
        # request.session['LogoutRequestID'] = auth.get_last_request_id()
        # return HttpResponseRedirect(slo_built_url)
    elif 'acs' in req['get_data']:
        request_id = None
        if 'AuthNRequestID' in request.session:
            request_id = request.session['AuthNRequestID']

        auth.process_response(request_id=request_id)
        errors = auth.get_errors()
        not_auth_warn = not auth.is_authenticated()

        if not errors:
            if 'AuthNRequestID' in request.session:
                del request.session['AuthNRequestID']
            request.session['samlUserdata'] = auth.get_attributes()
            request.session['samlNameId'] = auth.get_nameid()
            request.session['samlNameIdFormat'] = auth.get_nameid_format()
            request.session['samlNameIdNameQualifier'] = auth.get_nameid_nq()
            request.session['samlNameIdSPNameQualifier'] = auth.get_nameid_spnq()
            request.session['samlSessionIndex'] = auth.get_session_index()
            if 'RelayState' in req['post_data'] and OneLogin_Saml2_Utils.get_self_url(req) != req['post_data']['RelayState']:
                # To avoid 'Open Redirect' attacks, before execute the redirection confirm
                # the value of the req['post_data']['RelayState'] is a trusted URL.
                return HttpResponseRedirect(auth.redirect_to(req['post_data']['RelayState']))
        elif auth.get_settings().is_debug_active():
            error_reason = auth.get_last_error_reason()
    elif 'sls/' in request.get_full_path():
        print(request.get_full_path())
        request_id = None
        if 'LogoutRequestID' in request.session:
            request_id = request.session['LogoutRequestID']
        dscb = lambda: request.session.flush()
        url = auth.process_slo(request_id=request_id, delete_session_cb=dscb)
        errors = auth.get_errors()
        if len(errors) == 0:
            if url is not None:
                # To avoid 'Open Redirect' attacks, before execute the redirection confirm
                # the value of the url is a trusted URL
                return HttpResponseRedirect(url)
            else:
                success_slo = True
        elif auth.get_settings().is_debug_active():
            error_reason = auth.get_last_error_reason()

    if 'samlUserdata' in request.session:
        paint_logout = True
        if len(request.session['samlUserdata']) > 0:
            attributes = request.session['samlUserdata'].items()

    return render(request, 'index.html', {'errors': errors, 'error_reason': error_reason, 'not_auth_warn': not_auth_warn, 'success_slo': success_slo,
                                          'attributes': attributes, 'paint_logout': paint_logout})


def attrs(request):
    paint_logout = False
    attributes = False

    if 'samlUserdata' in request.session:
        paint_logout = True
        if len(request.session['samlUserdata']) > 0:
            attributes = request.session['samlUserdata'].items()
    return render(request, 'attrs.html',
                  {'paint_logout': paint_logout,
                   'attributes': attributes})


def metadata(request):
    # req = prepare_django_request(request)
    # auth = init_saml_auth(req)
    # saml_settings = auth.get_settings()
    (sp_key, sp_cert) = get_sp_id_info()
    idp_cert = get_idp_id_info()
    settings = get_saml_settings(sp_key, sp_cert, idp_cert)
    saml_settings = OneLogin_Saml2_Settings(settings, sp_validation_only=True)
    metadata = saml_settings.get_sp_metadata()
    errors = saml_settings.validate_metadata(metadata)

    if len(errors) == 0:
        resp = HttpResponse(content=metadata, content_type='text/xml')
    else:
        resp = HttpResponseServerError(content=', '.join(errors))
    return resp
