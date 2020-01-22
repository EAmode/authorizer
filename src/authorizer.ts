import { contains, find, is, path, whereEq } from 'ramda'

// export interface Policy {
//   name?
//   selector(resourceType, actionType, subjectType): boolean
//   authorize(request: AccessRequest, authorizer: Authorizer)
// }

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
  matcher?: (accessRequest: AccessRequest, authz?: Authorizer) => boolean
  mapper?: (resource) => object
}
export class Authorizer {
  constructor(public defaultPolicyChain: AccessRule[] = []) {}

  enforce(accessRequest: AccessRequest, policyChain?: AccessRule[]) {
    const response = this.applyChain(accessRequest, policyChain)
    return response.effect === RuleEffect.deny
      ? this.applyChain(accessRequest, this.defaultPolicyChain)
      : response
  }

  contains(obj, objPath, match): boolean {
    if (is(String, objPath)) {
      objPath = Array.of(objPath)
    }
    const p = path(objPath, obj) as any
    if (is(Array, p)) {
      const result = find(whereEq(match), p)
      return !!result
    } else {
      return contains(match, [p])
    }
  }

  private applyChain(accessRequest: AccessRequest, policyChain?: AccessRule[]) {
    const { subject, action, resource, environment } = accessRequest
    const response = { effect: RuleEffect.deny } as AccessResponse

    const applicableRules = policyChain
      ? policyChain.filter(r =>
          r.filter ? r.filter(resource.type, action.type) : true
        )
      : []

    for (const rule of applicableRules) {
      const matched = rule.matcher ? rule.matcher(accessRequest, this) : true

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
}
