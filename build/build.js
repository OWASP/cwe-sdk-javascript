'use strict'

const path = require('path')
const debug = require('debug')('cwe-sdk:build')
const { convertXmlArchiveToJson, writeJsonToFile, createCweDictionary } = require('./xmlParser')

debug('begin building CWE assets')

// @TODO add a script that creates a copy of cwec_v4.1.xml to
// its alias cwe-archive.xml
const RAW_INPUT_XML_FILENAME = 'cwe-archive.xml'
const RAW_OUTPUT_JSON_FILENAME = 'cwe-archive.json'
const OUTPUT_JSON_DICT_FILENAME = 'cwe-dictionary.json'
const OUTPUT_JSON_HIERARCHY_FILENAME = 'cwe-hierarchy.json'

const rawJsonCweArchive = convertXmlArchiveToJson({
  cweArchiveFilepath: path.join(__dirname, '..', 'raw', RAW_INPUT_XML_FILENAME)
})
writeJsonToFile({
  jsonFilepath: path.join(__dirname, '..', 'raw', RAW_OUTPUT_JSON_FILENAME),
  jsonData: rawJsonCweArchive
})

const { cweDictionary, cweHierarchy } = createCweDictionary({ cweArchive: rawJsonCweArchive })

writeJsonToFile({
  jsonFilepath: path.join(__dirname, '..', 'raw', OUTPUT_JSON_DICT_FILENAME),
  jsonData: cweDictionary
})

writeJsonToFile({
  jsonFilepath: path.join(__dirname, '..', 'raw', OUTPUT_JSON_HIERARCHY_FILENAME),
  jsonData: cweHierarchy
})

debug('finished')
