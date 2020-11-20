'use strict'

const path = require('path')
const debug = require('debug')('cwe-sdk:build')
const { convertXmlArchiveToJson, writeJsonToFile, createCweDictionary } = require('./xmlParser')
const request = require('./httpClient')
const AdmZip = require('adm-zip')
const { rename } = require('fs').promises

// @TODO add a script that creates a copy of cwec_v4.1.xml to
// its alias cwe-archive.xml
const RAW_INPUT_XML_FILENAME = 'cwe-archive.xml'
const RAW_OUTPUT_JSON_FILENAME = 'cwe-archive.json'
const OUTPUT_JSON_DICT_FILENAME = 'cwe-dictionary.json'
const OUTPUT_JSON_HIERARCHY_FILENAME = 'cwe-hierarchy.json'
const OUTPUT_JSON_MEMBERSHIPS_FILENAME = 'cwe-memberships.json'
const ARCHIVE_DOWNLOAD_OPTIONS = {
  hostname: 'cwe.mitre.org',
  port: 443,
  path: '/data/xml/cwec_latest.xml.zip',
  method: 'GET'
}
let cweArchiveVersion

debug('begin downloading latest CWE archive')

updateArchive()
  .then(() => {
    debug(`archive updated to version ${cweArchiveVersion}`)
    debug('begin building CWE assets')

    const rawJsonCweArchive = convertXmlArchiveToJson({
      cweArchiveFilepath: path.join(__dirname, '..', 'raw', RAW_INPUT_XML_FILENAME)
    })
    writeJsonToFile({
      jsonFilepath: path.join(__dirname, '..', 'raw', RAW_OUTPUT_JSON_FILENAME),
      jsonData: rawJsonCweArchive
    })

    const { cweDictionary, cweHierarchy, cweMemberships } = createCweDictionary({
      cweArchive: rawJsonCweArchive
    })

    writeJsonToFile({
      jsonFilepath: path.join(__dirname, '..', 'raw', OUTPUT_JSON_DICT_FILENAME),
      jsonData: cweDictionary
    })

    writeJsonToFile({
      jsonFilepath: path.join(__dirname, '..', 'raw', OUTPUT_JSON_HIERARCHY_FILENAME),
      jsonData: cweHierarchy
    })

    writeJsonToFile({
      jsonFilepath: path.join(__dirname, '..', 'raw', OUTPUT_JSON_MEMBERSHIPS_FILENAME),
      jsonData: cweMemberships
    })

    debug('finished')
  })
  .catch(console.error)

async function updateArchive() {
  const { data } = await request(ARCHIVE_DOWNLOAD_OPTIONS)

  const zip = new AdmZip(data)
  const zippedFile = zip.getEntries()[0].entryName
  cweArchiveVersion = zippedFile.substring(zippedFile.search(/v/) + 1, zippedFile.search(/\.xml/))
  zip.extractEntryTo(zippedFile, 'raw', false)
  return rename(
    path.join(__dirname, '..', 'raw', zippedFile),
    path.join(__dirname, '..', 'raw', RAW_INPUT_XML_FILENAME)
  )
}
