import { Authorizer, AuthzRequest, Policy } from '../src/authorizer'

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

  it('should default to authorize everything', () => {
    const authz = new Authorizer(policies)
    event.subject = user.admin
    const authedEvent = authz.authorizeEvent(event)
    expect(authedEvent).toEqual(event)
  })
})
