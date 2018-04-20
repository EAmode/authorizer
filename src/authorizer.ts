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
  authorize(request: AccessRequest, authorizer: Authorizer)
}

export interface AccessRequest {
  subject?
  action
  resource
  environment?
}

export enum RuleEffect {
  allow = 'allow',
  deny = 'deny'
}

export interface AccessResponse {
  effect: RuleEffect | string
  matchedRule?: AccessRule
  resource?
}

export interface AccessRule {
  effect: RuleEffect | string
  filter?: (resourceType, actionType) => boolean
  matcher?: (accessRequest: AccessRequest) => boolean
  mapper?: (resource) => object
}
export class Authorizer {
  byOrder = descend(prop('order'))

  constructor(public defaultPolicyChain: AccessRule[] = []) {}

  enforce(accessRequest: AccessRequest, policyChain?: AccessRule[]) {
    const response = this.applyChain(accessRequest, policyChain)
    return response.effect === RuleEffect.deny
      ? this.applyChain(accessRequest, this.defaultPolicyChain)
      : response
  }

  private applyChain(accessRequest: AccessRequest, policyChain?: AccessRule[]) {
    const { subject, action, resource, environment } = accessRequest
    const response = { effect: RuleEffect.deny } as AccessResponse

    const applicableRules = policyChain
      ? policyChain.filter(
          r => (r.filter ? r.filter(resource.type, action.type) : true)
        )
      : []

    for (const rule of applicableRules) {
      const matched = rule.matcher ? rule.matcher(accessRequest) : true

      if (matched) {
        response.effect = rule.effect
        response.matchedRule = rule
        break
      }
    }

    if (response.effect === RuleEffect.allow) {
      response.resource = response.matchedRule.mapper
        ? response.matchedRule.mapper(resource)
        : resource
    }

    return response
  }

  selectorMatch = p => p.selector()

  contains(resource, match, objPath) {
    const result = contains(match, path(objPath, resource))
    return result
  }

  getPolicyFor(resourceType: string, actionType: string, subjectType: string) {
    // const ps = sort<Policy>(this.byOrder, this.policyChains)
    // const foundPolicies = head(
    //   filter(
    //     (p: Policy) => p.selector(resourceType, actionType, subjectType),
    //     ps
    //   )
    // )
    // return foundPolicies
  }

  authorize(resource, action, subject, environment = {}) {
    // const foundPolicy = this.getPolicyFor(
    //   resource.type,
    //   action.type,
    //   subject.type
    // )
    // if (foundPolicy) {
    //   const hasAccess = foundPolicy.authorize(
    //     { resource, action, subject, environment },
    //     this
    //   )
    //   return hasAccess ? resource : undefined
    // } else {
    //   return resource
    // }
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
