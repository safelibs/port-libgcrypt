#include <libxml/parser.h>
#include <libxml/tree.h>
#include <stdio.h>
#include <xmlsec/crypto.h>
#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#include <xmlsec/xmldsig.h>

int main(int argc, char **argv) {
    if (argc != 2) {
        return 2;
    }

    xmlDocPtr doc = NULL;
    xmlNodePtr node = NULL;
    xmlSecDSigCtxPtr dsigCtx = NULL;
    xmlSecKeysMngrPtr mngr = NULL;

    xmlInitParser();
    LIBXML_TEST_VERSION
    xmlLoadExtDtdDefaultValue = XML_DETECT_IDS | XML_COMPLETE_ATTRS;
    xmlSubstituteEntitiesDefault(1);

    if (xmlSecInit() < 0) {
        return 3;
    }
    if (xmlSecCheckVersion() != 1) {
        return 4;
    }
    if (xmlSecCryptoAppInit(NULL) < 0) {
        return 5;
    }
    if (xmlSecCryptoInit() < 0) {
        return 6;
    }

    mngr = xmlSecKeysMngrCreate();
    if (mngr == NULL) {
        return 7;
    }
    if (xmlSecCryptoAppDefaultKeysMngrInit(mngr) < 0) {
        return 8;
    }

    doc = xmlParseFile(argv[1]);
    if (doc == NULL) {
        return 10;
    }
    node = xmlSecFindNode(xmlDocGetRootElement(doc), xmlSecNodeSignature, xmlSecDSigNs);
    if (node == NULL) {
        return 11;
    }

    dsigCtx = xmlSecDSigCtxCreate(mngr);
    if (dsigCtx == NULL) {
        return 12;
    }
    if (xmlSecDSigCtxVerify(dsigCtx, node) < 0) {
        return 13;
    }
    if (dsigCtx->status != xmlSecDSigStatusSucceeded) {
        return 14;
    }

    puts("xmlsec-gcrypt-rsa-verify-ok");

    xmlSecDSigCtxDestroy(dsigCtx);
    xmlFreeDoc(doc);
    xmlSecKeysMngrDestroy(mngr);
    xmlSecCryptoShutdown();
    xmlSecCryptoAppShutdown();
    xmlSecShutdown();
    xmlCleanupParser();
    return 0;
}
