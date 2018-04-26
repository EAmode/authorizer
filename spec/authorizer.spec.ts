import {
  AccessRequest,
  AccessRule,
  Authorizer,
  Policy,
  RuleEffect
} from '../src/authorizer'

describe('Authorization for ABAC', () => {
  const user = {
    anonymous: null,
    admin: {
      connections: {
        memberOf: [{ key: 'group::modeadmin', type: 'organization' }]
      }
    },
    payrollManager: {
      connections: { memberOf: [{ key: 'group::payroll' }] }
    }
  }

  const event = {
    actions: [{ type: 'create' }],
    object: {
      key: 'organization::eamode',
      type: 'organization',
      name: 'EA MODE'
    }
  } as any

  const accessRequest = {
    subject: user.admin,
    action: { type: 'read' },
    resource: {
      type: 'person',
      firstname: 'John',
      lastname: 'Doe',
      ssn: '123456789'
    }
  }

  it('anaymous should only see last 4 digits of SSN', () => {
    const authz = new Authorizer()
    const ar = authz.enforce(accessRequest, [
      {
        effect: 'allow',
        filter: rt => rt === 'person',
        mapper: resource => {
          if (resource.ssn) {
            resource.ssn = resource.ssn.substr(resource.ssn.length - 4)
          }
          return resource
        }
      }
    ])
    expect(ar.resource.ssn).toEqual('6789')
  })

  it('should not match', () => {
    const defaultRule = {
      effect: 'allow',
      matcher: ({ resource }) => resource.firstname === 'Doe'
    }
    const authz = new Authorizer([defaultRule])
    const ar = authz.enforce(accessRequest)
    expect(ar.effect).toEqual(RuleEffect.deny)
  })

  it('should match', () => {
    const defaultRule = {
      effect: 'allow',
      matcher: ({ resource }) => resource.firstname === 'John'
    }
    const authz = new Authorizer([defaultRule])
    const ar = authz.enforce(accessRequest)
    expect(ar.effect).toEqual(RuleEffect.allow)
  })

  it('should filter', () => {
    const defaultRule = { effect: 'allow', filter: (_, at) => at === 'read' }
    const authz = new Authorizer([defaultRule])
    const writeRule = { effect: 'allow', filter: (_, at) => at === 'write' }
    let ar = authz.enforce(accessRequest, [writeRule])
    expect(ar.matchedRule).toEqual(defaultRule)

    ar = authz.enforce({ action: { type: 'write' }, resource: {} }, [writeRule])
    expect(ar.matchedRule).toEqual(writeRule)
  })

  it('should apply default policy chain', () => {
    const authz = new Authorizer([{ effect: 'allow' }])
    const ar = authz.enforce(accessRequest, [{ effect: 'deny' }])
    expect(ar.effect).toEqual(RuleEffect.allow)
  })

  it('should allow with various allow defaults', () => {
    const authz = new Authorizer()
    let ar = authz.enforce(accessRequest, [{ effect: 'allow' }])
    expect(ar.effect).toEqual(RuleEffect.allow)
    ar = authz.enforce(accessRequest, [{ effect: 'allow', filter: () => true }])
    expect(ar.effect).toEqual(RuleEffect.allow)
    ar = authz.enforce(accessRequest, [
      { effect: 'allow', filter: () => true, matcher: () => true }
    ])
    expect(ar.effect).toEqual(RuleEffect.allow)
  })

  it('should deny with various allow defaults', () => {
    const authz = new Authorizer()
    let ar = authz.enforce(accessRequest, [{ effect: 'deny' }])
    expect(ar.effect).toEqual(RuleEffect.deny)
    ar = authz.enforce(accessRequest, [{ effect: 'deny', filter: () => true }])
    expect(ar.effect).toEqual(RuleEffect.deny)
    ar = authz.enforce(accessRequest, [
      { effect: 'deny', filter: () => true, matcher: () => true }
    ])
    expect(ar.effect).toEqual(RuleEffect.deny)
  })

  it('should deny any request if no policies are provided', () => {
    const authz = new Authorizer()
    const accessResponse1 = authz.enforce(accessRequest)
    expect(accessResponse1.effect).toEqual(RuleEffect.deny)
    const accessResponse2 = authz.enforce(accessRequest, [])
    expect(accessResponse2.effect).toEqual(RuleEffect.deny)
    const accessResponse3 = authz.enforce(accessRequest, null)
    expect(accessResponse3.effect).toEqual(RuleEffect.deny)
  })
})
