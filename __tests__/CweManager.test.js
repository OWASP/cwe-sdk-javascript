const { CweManager } = require('../index')

describe('Cwe Manager', () => {
  describe('Cwe Manager supports instantiation with custom data', () => {
    test('Cwe Manager instnatiated with custom hierarchy', () => {
      const cweManager = new CweManager({
        cweHierarchy: [{ weaknessId: '31337', parentId: '31338' }]
      })
      const result = cweManager.isChildOf({ weaknessId: '31337', parentId: '31338' })
      expect(result).toBe(true)
    })

    test.todo('Cwe Manager instnatiated with custom dictionary')
  })

  describe('Cwe Manager getters', () => {
    test.todo('Implement and test getByIds() with one id')
    test.todo('Implement and test getByIds() with multiple ids')
    test.todo('Implement and test getByIds() - what happens when no results?')
    test.todo('Implement and test getParents()')
    test.todo('Implement and test getChilds()')
  })

  describe('Testing CWE hierarchy', () => {
    test('A CWE ID that is a child of another CWE ID should return true', () => {
      const cweManager = new CweManager()
      const result = cweManager.isChildOf({ weaknessId: '117', parentId: '116' })
      expect(result).toBe(true)
    })

    test('A CWE ID that is not a child of another CWE ID should return false', () => {
      const cweManager = new CweManager()
      const result = cweManager.isChildOf({ weaknessId: '117', parentId: '52' })
      expect(result).toBe(false)
    })

    test('A CWE ID that is a child of an indirect CWE ID parent should return true', () => {
      const cweManager = new CweManager()
      const result = cweManager.isChildOf({ weaknessId: '117', parentId: '707', indirect: true })
      expect(result).toBe(true)
    })

    test('A CWE ID that is not a child of an indirect CWE ID parent should return false', () => {
      const cweManager = new CweManager()
      const result = cweManager.isChildOf({ weaknessId: '117', parentId: '22', indirect: true })
      expect(result).toBe(false)
    })

    test.todo(
      'A set of CWE IDs that are childs of another CWE ID should return true (one parent for all)'
    )
  })

  describe('Cwe Manager Memberships', () => {
    test('A CWE ID that has no memberships should return null', () => {
      const cweManager = new CweManager()
      const result = cweManager.getMemberships({ weaknessId: 'notfoundid' })
      expect(result).toBe(null)
    })

    test('A CWE ID with memberships should return an array of ids', () => {
      const cweManager = new CweManager()
      const result = cweManager.getMemberships({ weaknessId: '778' })
      expect(result).toStrictEqual(['1009', '1036', '1210', '1308', '1355', '1413'])
    })
  })
})
