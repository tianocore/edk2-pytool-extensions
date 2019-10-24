##
# This plugin installs a helper that platform build can invoke RsaPkcs1Signer to sign a binary.
#
# Copyright (c) Microsoft Corporation
#
##

from MuEnvironment import PluginManager
from MuPythonLibrary.UtilityFunctions import RunCmd
from OpenSSL import crypto

import logging
import os


class Pkcs1SignerHelper(PluginManager.IUefiHelperPlugin):

    def RegisterHelpers(self, obj):
        fp = os.path.abspath(__file__)
        obj.Register("Pkcs1TestSign", Pkcs1SignerHelper.Pkcs1TestSign, fp)

    @staticmethod
    def Pkcs1TestSign(fileToSign, sigFile, signingInfo):
        logging.debug("Executing PKCS1 Signing on " + fileToSign)
        logging.debug("Signing with " + signingInfo['pfxfile'])
        with open(signingInfo['pfxfile'], "rb") as pfxfile, open(fileToSign, "rb") as inputData, open(sigFile, "wb") as outputSig:
            pkcs12 = crypto.load_pkcs12(pfxfile.read())
            outputSig.write(crypto.sign(pkcs12.get_privatekey(),inputData.read(), "sha256"))
        return 0


