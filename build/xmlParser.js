'use strict'

/* eslint-disable security/detect-object-injection */
/* eslint-disable security/detect-non-literal-fs-filename */
const fs = require('fs')
const parser = require('fast-xml-parser')
const debug = require('debug')('cwe-sdk:build')

function createCweDictionary({ cweArchive }) {
  const allWeaknesses = cweArchive.Weakness_Catalog.Weaknesses.Weakness
  const allCategories = cweArchive.Weakness_Catalog.Categories.Category
  const membershipMap = new Map()
  allCategories
    .filter(category => category.Relationships)
    .forEach(category => {
      const memberIds = Array.from(category.Relationships.Has_Member).map(
        member => member.attr['@_CWE_ID']
      )
      memberIds.forEach(memberId => {
        const current = membershipMap.get(memberId) || []
        current.push(category.attr['@_ID'])
        membershipMap.set(memberId, current)
      })
    })
  const cweDictionary = {}
  const cweHierarchy = []
  const cweMemberships = []

  allWeaknesses.forEach(function(weakness) {
    const weaknessId = weakness['attr']['@_ID']
    cweDictionary[weaknessId] = weakness

    if (weakness['Related_Weaknesses'] && weakness['Related_Weaknesses']['Related_Weakness']) {
      const relatedWeaknesses = weakness['Related_Weaknesses']['Related_Weakness']

      if (Array.isArray(relatedWeaknesses)) {
        relatedWeaknesses.forEach(function(relation) {
          if (relation['attr']['@_Nature'] === 'ChildOf') {
            const parentId = relation['attr']['@_CWE_ID']
            cweHierarchy.push({
              weaknessId,
              parentId
            })
          }
        })
      } else {
        if (relatedWeaknesses['attr']['@_Nature'] === 'ChildOf') {
          const parentId = relatedWeaknesses['attr']['@_CWE_ID']
          cweHierarchy.push({
            weaknessId,
            parentId
          })
        }
      }

      const weaknessMembership = membershipMap.get(weaknessId)
      if (weaknessMembership) {
        cweMemberships.push({
          weaknessId,
          memberships: weaknessMembership
        })
      }
    }
  })

  return {
    cweDictionary,
    cweHierarchy,
    cweMemberships
  }
}

function convertXmlArchiveToJson({ cweArchiveFilepath }) {
  // @TODO debug for cweArchiveFilepath
  const xmlData = fs.readFileSync(cweArchiveFilepath, 'utf-8').toString()

  const options = {
    attributeNamePrefix: '@_',
    attrNodeName: 'attr',
    textNodeName: '#text',
    ignoreAttributes: false,
    ignoreNameSpace: false,
    allowBooleanAttributes: false,
    parseNodeValue: true,
    parseAttributeValue: false,
    trimValues: true,
    parseTrueNumberOnly: false,
    arrayMode: false
  }

  if (parser.validate(xmlData) !== true) {
    // @TODO xmlData is not valid
  }

  const rawJsonCweArchive = parser.parse(xmlData, options)
  return rawJsonCweArchive
}

function writeJsonToFile({ jsonFilepath, jsonData }) {
  debug(`writing JSON file to: ${jsonFilepath}`)
  fs.writeFileSync(jsonFilepath, JSON.stringify(jsonData))
}

module.exports = {
  createCweDictionary,
  convertXmlArchiveToJson,
  writeJsonToFile
}
