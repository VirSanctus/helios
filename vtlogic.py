import os
import hashlib
import logging
import requests
import json


def sha256sum(filename):
    with open(filename, 'rb') as f:
        m = hashlib.sha256()
        while True:
            data = f.read(8192)
            if not data:
                break
            m.update(data)
        return m.hexdigest()


class VirusTotalApi:
    def __init__(self):
        self.api_key = ''
        self.vt_url = 'https://www.virustotal.com/vtapi/v2'
        self.HTTP_OK = 200
        self.logger = logging.getLogger("vt-log")
        self.logger.setLevel(logging.INFO)
        self.scr_log = logging.StreamHandler()
        self.scr_log.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
        self.logger.addHandler(self.scr_log)
        self.is_verbose_log = False

    def retrieve_report(self, checksum):
        params = {'apikey': self.api_key, "resource": checksum}
        url = self.vt_url + "file/report"
        res = requests.get(url, data=params)
        return res

    def retrieve_files_reports(self, filenames):
        for filename in filenames:
            res = self.retrieve_report(sha256sum(filename))

            if res.status_code == self.HTTP_OK:
                resmap = json.loads(res.text)
                if not self.is_verbose_log:
                    self.logger.info(
                        "retrieve report: %s, HTTP: %d, response_code: %d, scan_date: %s, positives/total: %d/%d",
                        os.path.basename(filename), res.status_code, resmap["response_code"], resmap["scan_date"],
                        resmap["positives"], resmap["total"])
                else:
                    self.logger.info("retrieve report: %s, HTTP: %d, content: %s", os.path.basename(filename),
                                     res.status_code, res.text)
            else:
                self.logger.warning("retrieve report: %s, HTTP: %d", os.path.basename(filename), res.status_code)

    def send_files(self, filenames):
        url = self.vt_url + "file/scan"
        params = {"apikey": self.api_key}

        for file in filenames:
            files = {"file": open(file, 'rb')}
            res = requests.post(url, data=params, files=files)

            if res.status_code == self.HTTP_OK:
                resmap = json.loads(res.text)
                if not self.is_verbose_log:
                    self.logger.info("sent: %s, HTTP: %d, response_code: %d, scan_id: %s",
                                     os.path.basename(file), res.status_code, resmap["response_code"],
                                     resmap["scan_id"])
                else:
                    self.logger.info("sent: %s, HTTP: %d, content: %s", os.path.basename(file), res.status_code,
                                     res.text)
            else:
                self.logger.info("sent: %s, HTTP: %d", os.path.basename(file), res.status_code)
