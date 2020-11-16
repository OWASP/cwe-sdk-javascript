'use strict'

const CWE_HIERARCHY = require('../raw/cwe-hierarchy.json')
const CWE_DICTIONARY = require('../raw/cwe-dictionary.json')
const CWE_MEMBERSHIPS = require('../raw/cwe-memberships.json')
const debug = require('debug')('cwe-sdk:manager')

module.exports = class CweManager {
  constructor({ cweHierarchy = null, cweDictionary = null, cweMemberships = null } = {}) {
    if (cweHierarchy) {
      debug('manager received cweHierarchy to be used')
      this.cweHierarchy = cweHierarchy
    } else {
      this.cweHierarchy = CWE_HIERARCHY
    }

    if (cweDictionary) {
      debug('manager received cweDictionary to be used')
      this.cweDictionary = cweDictionary
    } else {
      this.cweDictionary = CWE_DICTIONARY
    }

    if (cweMemberships) {
      debug('manager received cweMemberships to be used')
      this.cweMemberships = cweMemberships
    } else {
      this.cweMemberships = CWE_MEMBERSHIPS
    }
  }

  getMemberships({ weaknessId }) {
    const weakness = this.cweMemberships.find(weakness => weakness.weaknessId === weaknessId)
    if (!weakness) {
      return null
    }
    return weakness.memberships
  }

  isChildOf({ indirect = false, weaknessId, parentId }) {
    if (indirect === true) {
      return this.isChildOfIndirect({ weaknessId, parentId })
    }

    const foundMatch = this.cweHierarchy.find(weakness => {
      return weakness.weaknessId === weaknessId && weakness.parentId === parentId
    })

    return !!foundMatch
  }

  isChildOfIndirect({ weaknessId, parentId }) {
    const foundMatch = this.cweHierarchy.find(weakness => {
      if (weakness.weaknessId === weaknessId) {
        if (weakness.parentId === parentId) {
          return true
        } else {
          return this.isChildOfIndirect({ weaknessId: weakness.parentId, parentId })
        }
      }
    })

    return !!foundMatch
  }
}
