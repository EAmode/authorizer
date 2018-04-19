import {
  any,
  apply,
  ascend,
  contains,
  descend,
  equals,
  filter,
  find,
  head,
  map,
  path,
  pickAll,
  prop,
  sort,
  where
} from 'ramda'

export interface Policy {
  name?
  selector(resourceType, actionType, subjectType): boolean
  authorize(request: AuthzRequest, authorizer: Authorizer)
}

export interface AuthzRequest {
  subject?
  action?
  resource?
  environment?
}

export class Authorizer {
  byOrder = descend(prop('order'))

  constructor(public policies: Policy[] = []) {}

  selectorMatch = p => p.selector()

  contains(resource, match, objPath) {
    const result = contains(match, path(objPath, resource))
    return result
  }

  getPolicyFor(resourceType: string, actionType: string, subjectType: string) {
    const ps = sort<Policy>(this.byOrder, this.policies)
    const foundPolicies = head(
      filter(
        (p: Policy) => p.selector(resourceType, actionType, subjectType),
        ps
      )
    )
    return foundPolicies
  }

  authorize(resource, action, subject, environment = {}) {
    const foundPolicy = this.getPolicyFor(
      resource.type,
      action.type,
      subject.type
    )
    if (foundPolicy) {
      const hasAccess = foundPolicy.authorize(
        { resource, action, subject, environment },
        this
      )
      return hasAccess ? resource : undefined
    } else {
      return resource
    }
  }

  authorizeEvent(event) {
    const newEvent = { ...event }
    let resource = newEvent.object ? newEvent.object : newEvent.connection
    for (const action of event.actions) {
      if (action.type === 'create') {
        resource = this.authorize(event.object, action, event.subject)
      }
      if (action.type === 'modify') {
        const combined = Object.assign(event.object, action.data)
        resource = this.authorize(event.object, action, event.subject)
        if (resource) {
          action.data = pickAll(action.data.keys(), resource)
          if (!action.data) {
            action.data = undefined
          }
        }
      }
    }
    return newEvent
  }
}
