# -*- coding: UTF-8 -*-
import json
import os
import re
import sqlite3
import sys
from random import randint

import requests
import yaml
from lxml import etree

requests.packages.urllib3.disable_warnings()

ISUPDATE = False


def sendPlugin(j):
    authToken = ""
    conn = sqlite3.connect("C:\\Users\\dogs\\yakit-projects\\default-yakit.db")
    cursor = conn.cursor()
    sql = ''' SELECT value FROM main.general_storages WHERE key='"token-online"' '''
    cursor.execute(sql)
    authToken = cursor.fetchall()[0][0][1:-1]
    conn.close()

    # data = json.loads(json.dumps(j).encode('utf-8').decode('unicode_escape').encode('utf-8'))
    # print(j)
    # sys.exit(0)
    headers = {"User-Agent": "axios/0.26.1", "Authorization": authToken, "Content-Type": "application/json"}
    proxies = {'http': '127.0.0.1:8083', 'https': '127.0.0.1:8083'}
    x = requests.post("https://www.yaklang.com/api/yakit/plugin", json=j, headers=headers, verify=False)
    print(x.content.decode('utf-8'))
    if x.status_code != 200:
        return False
    return True


def crawPoc(path):
    # path = "C:\\Users\\dogs\\yakit-projects\\repos\\myplugins\\xray\\pocs"  # 文件夹目录
    nopoc = [
        "dedecms-guestbook-sqli", "drupal-cve-2018-7600-rce", "etcd-unauth", "flexpaper-cve-2018-11686",
        "gitlist-rce-cve-2018-1000533", "h2-database-web-console-unauthorized-access", "jenkins-unauthorized-access",
        "jira-cve-2019-11581", "joomla-cnvd-2019-34135-rce", "kyan-network-monitoring-account-password-leakage", "maccms-rce",
        "maccmsv10-backdoor", "minio-default-password", "netgear-cve-2017-5521", "nextjs-cve-2017-16877",
        "nhttpd-cve-2019-16278", "node-red-dashboard-file-read-cve-2021-3223", "novnc-url-redirection-cve-2021-3654",
        "nps-default-password", "ns-asg-file-read", "nsfocus-uts-password-leak", "nuuo-file-inclusion", "odoo-file-read",
        "openfire-cve-2019-18394-ssrf", "opentsdb-cve-2020-35476-rce", "panabit-gateway-default-password",
        "panabit-ixcache-default-password", "pandorafms-cve-2019-20224-rce", "pbootcms-database-file-download",
        "pentaho-cve-2021-31602-authentication-bypass", "php-cgi-cve-2012-1823", "phpcms-cve-2018-19127",
        "phpmyadmin-cve-2018-12613-file-inclusion", "phpmyadmin-setup-deserialization", "phpok-sqli", "phpshe-sqli",
        "phpstudy-nginx-wrong-resolve", "phpunit-cve-2017-9841-rce", "powercreator-arbitrary-file-upload",
        "prometheus-url-redirection-cve-2021-29622", "pulse-cve-2019-11510", "pyspider-unauthorized-access", "qibocms-sqli",
        "qilin-bastion-host-rce", "qizhi-fortressaircraft-unauthorized", "qnap-cve-2019-7192", "rabbitmq-default-password",
        "rails-cve-2018-3760-rce", "razor-cve-2018-8770", "rconfig-cve-2019-16663", "resin-cnnvd-200705-315",
        "resin-inputfile-fileread-or-ssrf", "resin-viewfile-fileread", "rockmongo-default-password", "ruijie-eg-cli-rce",
        "ruijie-eg-file-read", "ruijie-eg-info-leak", "ruijie-eweb-rce-cnvd-2021-09650", "ruijie-nbr1300g-cli-password-leak",
        "ruijie-uac-cnvd-2021-14536", "ruoyi-management-fileread", "saltstack-cve-2020-16846",
        "saltstack-cve-2021-25282-file-write", "samsung-wea453e-default-pwd", "samsung-wea453e-rce",
        "samsung-wlan-ap-wea453e-rce", "sangfor-edr-arbitrary-admin-login", "sangfor-edr-cssp-rce", "sangfor-edr-tool-rce",
        "satellian-cve-2020-7980-rce", "seacms-before-v992-rce", "seacms-rce", "seacms-sqli", "seacms-v654-rce",
        "seacmsv645-command-exec", "secnet-ac-default-password", "seeyon-ajax-unauthorized-access",
        "seeyon-cnvd-2020-62422-readfile", "seeyon-oa-cookie-leak", "seeyon-session-leak", "seeyon-wooyun-2015-0108235-sqli",
        "seeyon-wooyun-2015-148227", "shiziyu-cms-apicontroller-sqli", "shopxo-cnvd-2021-15822", "showdoc-default-password",
        "showdoc-uploadfile", "solarwinds-cve-2020-10148", "solr-cve-2017-12629-xxe", "solr-cve-2019-0193", "solr-fileread",
        "solr-velocity-template-rce", "sonarqube-cve-2020-27986-unauth", "sonicwall-ssl-vpn-rce", "spark-api-unauth",
        "spark-webui-unauth", "spon-ip-intercom-file-read", "spon-ip-intercom-ping-rce", "spring-cloud-cve-2020-5405",
        "spring-cloud-cve-2020-5410", "spring-cve-2016-4977", "springboot-env-unauth", "springcloud-cve-2019-3799",
        "supervisord-cve-2017-11610", "tamronos-iptv-rce", "telecom-gateway-default-password", "tensorboard-unauth",
        "terramaster-cve-2020-15568", "terramaster-tos-rce-cve-2020-28188", "thinkadmin-v6-readfile", "thinkcmf-lfi",
        "thinkcmf-write-shell", "thinkphp-v6-file-write", "thinkphp5-controller-rce", "thinkphp5023-method-rce",
        "tianqing-info-leak", "tomcat-cve-2017-12615-rce", "tomcat-cve-2018-11759", "tongda-meeting-unauthorized-access",
        "tongda-user-session-disclosure", "tpshop-directory-traversal", "tpshop-sqli", "tvt-nvms-1000-file-read-cve-2019-20085",
        "typecho-rce", "uwsgi-cve-2018-7490", "vbulletin-cve-2019-16759-bypass", "vbulletin-cve-2019-16759",
        "vmware-vcenter-arbitrary-file-read", "vmware-vcenter-cve-2021-21985-rce",
        "vmware-vcenter-unauthorized-rce-cve-2021-21972", "vmware-vrealize-cve-2021-21975-ssrf", "weaver-ebridge-file-read",
        "weblogic-cve-2019-2729-1", "weblogic-cve-2019-2729-2", "weiphp-path-traversal", "weiphp-sql",
        "wifisky-default-password-cnvd-2021-39012", "wordpress-cve-2019-19985-infoleak", "wordpress-ext-adaptive-images-lfi",
        "wordpress-ext-mailpress-rce", "wuzhicms-v410-sqli", "xdcms-sql", "xiuno-bbs-cvnd-2019-01348-reinstallation",
        "xunchi-cnvd-2020-23735-file-read", "yapi-rce", "yccms-rce", "yongyou-u8-oa-sqli", "yonyou-grp-u8-sqli-to-rce",
        "yonyou-grp-u8-sqli", "yonyou-nc-arbitrary-file-upload", "yonyou-nc-bsh-servlet-bshservlet-rce",
        "youphptube-encoder-cve-2019-5127", "youphptube-encoder-cve-2019-5128", "youphptube-encoder-cve-2019-5129",
        "yungoucms-sqli", "zcms-v3-sqli", "zeit-nodejs-cve-2020-5284-directory-traversal", "zeroshell-cve-2019-12725-rce",
        "zimbra-cve-2019-9670-xxe", "zzcms-zsmanage-sqli"
    ]
    files = os.listdir(path)  # 得到文件夹下的所有文件名称
    for file in files:  # 遍 历文件夹
        if not os.path.isdir(file):  # 判断是否是文件夹，不是文件夹才打开
            if file[:-4] in nopoc:
                with open(path + "/" + file, encoding='utf-8') as f:  # demo.yaml内容同上例yaml字符串
                    # print(yaml.safe_load(f))
                    # print(file)
                    poc = yaml.safe_load(f)
                    bulidPlugin(poc)


def bulidPlugin(poc):

    uploadBody = {
        "type":
        "port-scan",
        "script_name":
        "模块名",
        "content":
        "源码",
        "tags": ["tags"],
        "params": [{
            "field": "target",
            "default_value": "",
            "type_verbose": "string",
            "field_verbose": "扫描的目标",
            "help": "",
            "required": True,
            "group": "",
            "extra_setting": ""
        }, {
            "field": "ports",
            "default_value": "80",
            "type_verbose": "string",
            "field_verbose": "端口",
            "help": "",
            "required": False,
            "group": "",
            "extra_setting": ""
        }],
        "help":
        "描述",
        "contributors":
        "y1s3m0",
        "default_open":
        True,
        "plugin_selector_types":
        "mitm,port-scan",
        "is_general_module":
        False,
        "id":
        0
    }
    # print(uploadBody)
    if "poc-yaml" not in poc["name"]:
        print("drop not poc " + poc["name"])
        return False
    if "search" in str(poc["rules"]):
        print("drop search " + poc["name"])
        # drop search poc-yaml-dedecms-guestbook-sqli
        # drop search poc-yaml-drupal-cve-2018-7600-rce
        # drop search poc-yaml-gitlist-rce-cve-2018-1000533
        # drop search poc-yaml-h2-database-web-console-unauthorized-access
        # drop search poc-yaml-jenkins-unauthorized-access
        # drop search poc-yaml-jira-cve-2019-11581
        # drop search poc-yaml-joomla-cnvd-2019-34135-rce
        # drop search poc-yaml-kyan-network-monitoring-account-password-leakage
        # drop search poc-yaml-maccms-rce
        return False
    else:
        name = poc["name"][9:].split("-")
        tags = []
        n = 0
        cve = ""
        severity = ""
        while n < len(name):
            na = name[n]
            if na == "cve" or na == "cnvd":
                cve = na + "-" + name[n + 1] + "-" + name[n + 2]
                tags.append(cve)
                n += 3
            else:
                tags.append(na)
                n += 1
        # print(tags)

    if "description" in poc["detail"]:
        uploadBody["help"] = poc["detail"]["description"]
    elif "links" in poc["detail"]:
        uploadBody["help"] = "\n".join(poc["detail"]["links"])
    else:
        uploadBody["help"] = ""

    if len(cve) > 0:
        uploadBody["script_name"], uploadBody["help"], severity = getCve(cve)
    else:
        uploadBody["script_name"] = " ".join(tags) + " 漏洞"
        # print(uploadBody["script_name"])

    uploadBody["tags"] = tags

    # elasticsearch cve-2015-3337 lfi 漏洞
    # uploadBody["type"] = "port-scan"
    # elasticsearch cve-2015-3337 lfi

    # sys.exit(0)
    uploadBody["content"] = getContent(poc, severity, uploadBody["script_name"])
    if uploadBody["content"]:
        if ISUPDATE:
            uploadBody["id"] = getOnlineid(uploadBody["script_name"])
            print(uploadBody["id"])
        sendPlugin(uploadBody)
    # print(uploadBody["script_name"])
    # print(uploadBody["help"])
    # print(severity)
    # print("===========================================")
    # print(uploadBody)
    # print(uploadBody["content"])


def getCve(cve):
    url = "https://avd.aliyun.com/"
    # proxies = {'http': '127.0.0.1:8083', 'https': '127.0.0.1:8083'}
    severity = ""

    x = requests.get(url + "search?q=" + cve, verify=False)
    html = etree.HTML(x.content.decode('utf-8'))
    detal_url = html.xpath("//table/tbody/tr/td/a/@href")[0]

    y = requests.get(url + detal_url, verify=False)
    html = etree.HTML(y.content.decode('utf-8'))
    vuln_detal = html.xpath('//div[@class="text-detail pt-2 pb-4"]/div/text()')[0]
    vuln_title = html.xpath('//h5[@class="header__title"]/*/text()')
    if len(vuln_title) > 1:
        severity = vuln_title[0]
        script_name = vuln_title[1]
        # print(cve + ": " + severity)
    else:
        script_name = vuln_title[0]

    # print(cve + ": " + script_name)
    # print(cve + ": " + vuln_detal)

    return script_name, vuln_detal, severity


def getContent(poc, severity, reference):
    info = '''
    # type="文件上传"
    =level[3]
    reference="财务管理软件任意文件上传"
'''
    info = "\r\n    reference=\"" + reference + "\""
    info = info + "\r\n    severity=\"" + severity + "\""

    end_code = '''
    if vulnable {
            yakit.Info("FOUND INFO for %v", type)
            risk.NewRisk(
                url, risk.severity(severity), 
                # risk.title(sprintf("FOUND %v", type)),
                risk.titleVerbose(sprintf("%v", reference)),
                # risk.type(type), risk.typeVerbose(type),
                risk.details({
                    "request": resp.Request,
                    "response": resp,
                    "url": url,
                }),
            )
        }
    return
}
handle = func(result) {
    if !result.IsOpen(){
        return
    }
    if len(result.Fingerprint.HttpFlows)>0{
        handleCheck(result.Target,result.Port)
    }
}
'''
    start_code = '''yakit.AutoInitYakit()

handleCheck = func(target,port){
    addr = str.HostPort(target, port)
    isTls = str.IsTLSServer(addr)
    level=["low","middle","high","critical"]
    if isTls {
        url="https://"+addr
    }else{
        url="http://"+addr
    }
    vulnable=false
'''

    code = '''
    poc_url, _ = str.UrlJoin(url, "/plus/weixin.php")
    resp, _ := http.Request(method,poc_url,
        http.header(headers),
        http.body(body),
        http.noredirect(follow_redirects)
    )
'''
    dnslog = '''
    rand_Payload=str.RandStr(10)
    server,token,err = risk.NewDNSLogDomain()
    die(err)
    yakit.Info("dnslog server addr: %v ",server)
    yakit.Info("dnslog server check token: %v", token)
'''

    code = "\r\n"
    for r_key, r in dict.items(poc["rules"]):
        if "search" in r:
            print("drop" + poc["name"])
            return False
        if "path" in r["request"]:
            # code = code + "\r\n" + '    poc_url_' + r_key + ', _ = str.UrlJoin(url, `' + r["request"]["path"] + '`)'
            code = code + "\r\n" + '    poc_url_' + r_key + '= url + `' + r["request"]["path"] + '`'
        else:
            code = code + "\r\n" + '    poc_url_' + r_key + ' = url'

        code = code + "\r\n" + '    resp_' + r_key + ', _ := http.Request("' + r["request"][
            "method"] + '",poc_url_' + r_key + ','

        if "headers" in r["request"]:
            for name, value in dict.items(r["request"]["headers"]):
                code = code + "\r\n" + '    http.header(`' + name + '`,`' + value + '`),'

        if "body" in r["request"]:
            code = code + "\r\n" + '    http.body(`' + r["request"]["body"] + '`),'

        # if "follow_redirects" in r["request"]:
        #     redirect = "true" if r["request"]["follow_redirects"] else "false"
        #     code = code + "\r\n" + '    http.redirect(' + redirect + '),'
        code = code + ')'
        code = code + "\r\n" + '    bresp,_=http.dump(resp_' + r_key + ')'
        code = code + "\r\n" + '    header, body = poc.Split(bresp)'

        code = code + "\r\n    " + r_key + '_flag = false'
        if "expression" in r:
            pandan = r["expression"].replace("status", "StatusCode")
            pandan = pandan.replace("response.body.bcontains(bytes(", "str.Contains(string(body),string(")
            pandan = pandan.replace("response.body.bcontains(b\"", "str.Contains(string(body),\"")
            p = re.compile(r'response\.headers\[.*?\].*?\"(.*?)\"[\)]*')
            for match in p.finditer(pandan):
                pandan = p.sub("str.Contains(string(header),\"" + match.group(1) + "\")", pandan)

            p = re.compile(r'response\.content_type.*?\"(.*?)\"[\)]*')
            for match in p.finditer(pandan):
                pandan = p.sub("str.Contains(string(header),\"" + match.group(1) + "\")", pandan)

            p = re.compile(r'\s\"(.*?)\"\.bmatches\(response\.body\)')
            for match in p.finditer(pandan):
                pandan = p.sub(" re.Match(\"" + match.group(1) + "\",string(body))", pandan)
            pandan = pandan.replace("md5(", "codec.Md5(")
            pandan = pandan.replace("base64(", "codec.EncodeBase64(")
            pandan = pandan.replace("base64Decode(", "codec.DecodeBase64(")
            pandan = pandan.replace("urlencode(", "codec.EncodeUrl(")
            pandan = pandan.replace("urldecode(", "codec.DecodeUrl(")

            p = re.compile(r'substr\((.*?),(.*?),(.*?)\)')
            for match in p.finditer(pandan):
                pandan = p.sub(match.group(1) + "[" + match.group(2) + ":" + match.group(3) + "]", pandan)

            pandan = pandan.replace("response.headers", "response.Headers")
            pandan = pandan.replace("response.body", "body")
            pandan = pandan.replace("response.", "resp_" + r_key + ".")

            if "reverse" in r["expression"]:
                code = code + "\r\n" + '    detail, _ := risk.CheckDNSLogByToken(token)'
                # 	println("dnslog result: ", detail[0])
                # 	return true
                pandan = re.sub(r"reverse\.wait\(.*?\)", "len(detail) > 0 && str.Contains(detail[0],rand_Payload)", pandan)
            code = code + "\r\n" + '    if ' + pandan + '{'
            code = code + "\r\n\t" + r_key + '_flag = true'
            code = code + "\r\n" + '    }\r\n'

    code = code + '\r\n    resp=resp_' + r_key
    code = code + '\r\n    poc_url=poc_url_' + r_key
    if "expression" in poc:
        pandan = poc["expression"]
        for r_key, _ in dict.items(poc["rules"]):
            pandan = pandan.replace(r_key + "()", r_key + "_flag")
        code = code + "\r\n" + '    if ' + pandan + '{'
        code = code + "\r\n\t" + 'vulnable = true'
        code = code + "\r\n" + '    }'

    if "set" in poc:
        set_list = []
        reverse = False
        for set_key, set_value in dict.items(poc["set"]):
            set_list.append(set_key)
            # if "newReverse" in set_value:
            if "randomInt" in set_value:
                randomInt = randint(int(re.findall("\d+", set_value)[0]), int(re.findall("\d+", set_value)[1]))
                code = "\r\n" + '    ' + set_key + ' = ' + str(randomInt) + code
            elif "randomLowercase" in set_value:
                code = "\r\n" + '    ' + set_key + ' = str.RandStr(' + re.findall("\d+", set_value)[0] + ')' + code
            elif "everse" in set_value:
                if "reverse.url.host" in set_value:
                    dnslog = dnslog + "\r\n" + '    ' + set_key + ' =  rand_Payload+"."+server'
                elif "reverse.url.path" in set_value:
                    dnslog = dnslog + "\r\n" + '    ' + set_key + ' = ""'
                elif "reverse.url" in set_value:
                    dnslog = dnslog + "\r\n" + '    ' + set_key + ' =  "http://"+rand_Payload+"."+server'
                reverse = True
            else:
                return False  # request.url.host
            code = code.replace('{{' + set_key + '}}', '`+ string(' + set_key + ') +`')
        if reverse:
            code = dnslog + code
    # set()
    # set 中可以使用 request 和 reverse(下面讲到) 变量
    # 在 rules 的 expression 中可以直接使用自定义变量，非 expression 的部分需要使用 {{}} 包裹变量，因为其他位置不是表达式（类似 search)
    # https://docs.xray.cool/#/guide/poc/v1?id=%e5%a6%82%e4%bd%95%e7%bc%96%e5%86%99expression%e8%a1%a8%e8%be%be%e5%bc%8f
    # print(code)

    return start_code + info + code + end_code


def getOnlineid(script_name):
    conn = sqlite3.connect("C:\\Users\\dogs\\yakit-projects\\default-yakit.db")
    cursor = conn.cursor()
    sql = ''' SELECT online_id FROM main.yak_scripts WHERE script_name='%s' ''' % (script_name)
    cursor.execute(sql)
    authToken = cursor.fetchall()[0][0]
    conn.close()
    return int(authToken)


if __name__ == '__main__':
    path = "C:\\Users\\dogs\\yakit-projects\\repos\\myplugins\\xray\\pocs"
    crawPoc(path)

    # with open('C:\\Users\\dogs\\yakit-projects\\repos\\myplugins\\xray\\pocs\\weblogic-cve-2017-10271.yml',
    #           encoding='utf-8') as f:
    #     # print(yaml.safe_load(f))
    #     poc = yaml.safe_load(f)
    #     bulidPlugin(poc)

    # path = "C:\\Users\\dogs\\yakit-projects\\repos\\myplugins\\xray\\pocs"  # 文件夹目录
    # files = os.listdir(path)  # 得到文件夹下的所有文件名称
    # for file in files:  # 遍 历文件夹
    #     if not os.path.isdir(file):  # 判断是否是文件夹，不是文件夹才打开
    #         with open(path + "/" + file, encoding='utf-8') as f:  # demo.yaml内容同上例yaml字符串
    #             # print(yaml.safe_load(f))
    #             poc = yaml.safe_load(f)
    #             print(file + ":................")
    #             for r_key, r in dict.items(poc["rules"]):
    #                 code = ""
    #                 pandan = r["expression"].replace("status", "StatusCode")
    #                 pandan = pandan.replace("response.body.bcontains(bytes(", "str.Contains(string(body),string(")
    #                 pandan = pandan.replace("response.body.bcontains(b\"", "str.Contains(string(body),\"")
    #                 p = re.compile(r'response\.headers\[.*?\].*?\"(.*?)\"[\)]*')
    #                 for match in p.finditer(pandan):
    #                     pandan = p.sub("str.Contains(string(header),\"" + match.group(1) + "\")", pandan)

    #                 p = re.compile(r'response\.content_type.*?\"(.*?)\"[\)]*')
    #                 for match in p.finditer(pandan):
    #                     pandan = p.sub("str.Contains(string(header),\"" + match.group(1) + "\")", pandan)

    #                 p = re.compile(r'\s\"(.*?)\"\.bmatches\(response\.body\)')
    #                 for match in p.finditer(pandan):
    #                     pandan = p.sub(" re.Match(\"" + match.group(1) + "\",string(body))", pandan)
    #                 pandan = pandan.replace("md5(", "codec.Md5(")
    #                 pandan = pandan.replace("base64(", "codec.EncodeBase64(")
    #                 pandan = pandan.replace("base64Decode(", "codec.DecodeBase64(")
    #                 pandan = pandan.replace("urlencode(", "codec.EncodeUrl(")
    #                 pandan = pandan.replace("urldecode(", "codec.DecodeUrl(")

    #                 p = re.compile(r'substr\((.*?),(.*?),(.*?)\)')
    #                 for match in p.finditer(pandan):
    #                     pandan = p.sub(match.group(1) + "[" + match.group(2) + ":" + match.group(3) + "]", pandan)

    #                 pandan = pandan.replace("response.headers", "response.Headers")
    #                 pandan = pandan.replace("response.body", "body")
    #                 pandan = pandan.replace("response.", "resp_" + r_key + ".")
    #                 code = code + "\r\n" + '    if ' + pandan + '{'
    #                 code = code + "\r\n\t" + r_key + '_flag = true'
    #                 code = code + "\r\n" + '    }'
    #                 print(r["expression"])
    #                 print(code)
    #             print(poc["expression"])
