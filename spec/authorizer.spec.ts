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

  it('anaymous should only see last 4 digits od SSN', () => {
    const authz = new Authorizer()
    const ar = authz.enforce(accessRequest, [{ effect: 'allow', filter: rt => rt ==='person' }])
    expect(ar.effect).toEqual(RuleEffect.deny)
  })

  it('should not match', () => {
    const defaultRule = { effect: 'allow', matcher: ({resource}) => resource.firstname === 'Doe' }
    const authz = new Authorizer([defaultRule])
    const ar = authz.enforce(accessRequest)
    expect(ar.effect).toEqual(RuleEffect.deny)
  })

  it('should match', () => {
    const defaultRule = { effect: 'allow', matcher: ({resource}) => resource.firstname === 'John' }
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

  // ea mode   1 allow all to view [Id, Name, Shortname] of every object and change nothing
  //           2

  // |-- Organization   1 deny anonymous to view [*] of { Persons }
  //

  //     |-- Contractors   1 deny everyone everything
  //                       2 allow users to view everything
  //                       3 deny users to view
  const allowAdmin = {
    name: 'Allow MODE Admin everything',
    selector: _ => true,
    order: 0,
    authorize: (request, authz) => {
      const { subject } = request
      authz.contains(subject, { key: 'group::modeadmin' }, [
        'connections',
        'memberOf'
      ])
    }
  } as Policy

  const allowValidUsers = {
    name: 'Valid User',
    selector: (resourceType, actionType) => actionType === 'view',
    order: 1,
    authorize: (request, authz) => {
      const { subject } = request
      return subject.key !== 'user::anonymous'
    }
  } as Policy

  const allowContractor = {
    name: 'Contractor',
    selector: (resourceType, actionType) =>
      resourceType === 'person' && actionType === 'view',
    order: 2,
    authorize: (request, authz) => {
      const { subject, resource } = request
      return subject.id === resource.ownerId
    }
  } as Policy

  const policies = [allowAdmin, allowContractor]

  // it('should authorize everything', () => {
  //   const authz = authorization()
  //   const authedEvent = authz.authorizeEvent(event)
  //   expect(authedEvent).toEqual(event)
  // })

  // it('should default to authorize everything', () => {
  //   const authz = new Authorizer(policies)
  //   event.subject = user.admin
  //   const authedEvent = authz.authorizeEvent(event)
  //   expect(authedEvent).toEqual(event)
  // })
})
