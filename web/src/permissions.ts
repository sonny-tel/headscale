// Role-based permission model based on Tailscale's permission matrix.
// See: https://tailscale.com/kb/1138/user-roles#permission-matrix
//
// Headscale roles mapped to Tailscale:
//   admin        → Owner + Admin
//   network_admin → Network Admin
//   it_admin     → IT Admin
//   member       → Member (no admin console access)

export interface Permissions {
  canAccessAdmin: boolean;
  canViewMachines: boolean;
  canWriteMachines: boolean;
  canViewUsers: boolean;
  canWriteUsers: boolean;
  canViewACL: boolean;
  canWriteACL: boolean;
  canViewDNS: boolean;
  canWriteDNS: boolean;
  canManageAuthKeys: boolean;
  canManageAPIKeys: boolean;
  canViewLogs: boolean;
  canViewSettings: boolean;
  canViewServices: boolean;
  canWriteServices: boolean;
  canViewDebug: boolean;
}

const ADMIN: Permissions = {
  canAccessAdmin: true,
  canViewMachines: true,
  canWriteMachines: true,
  canViewUsers: true,
  canWriteUsers: true,
  canViewACL: true,
  canWriteACL: true,
  canViewDNS: true,
  canWriteDNS: true,
  canManageAuthKeys: true,
  canManageAPIKeys: true,
  canViewLogs: true,
  canViewSettings: true,
  canViewServices: true,
  canWriteServices: true,
  canViewDebug: true,
};

const NETWORK_ADMIN: Permissions = {
  canAccessAdmin: true,
  canViewMachines: true,
  canWriteMachines: false, // Can read but not write machines
  canViewUsers: true,
  canWriteUsers: false, // Can read but not write users
  canViewACL: true,
  canWriteACL: true, // Can write ACL/policy
  canViewDNS: true,
  canWriteDNS: true, // Can write DNS/network config
  canManageAuthKeys: true,
  canManageAPIKeys: true,
  canViewLogs: true,
  canViewSettings: true,
  canViewServices: true,
  canWriteServices: true, // Network setting like DNS
  canViewDebug: false,
};

const IT_ADMIN: Permissions = {
  canAccessAdmin: true,
  canViewMachines: true,
  canWriteMachines: true, // Can write machines
  canViewUsers: true,
  canWriteUsers: true, // Can write users
  canViewACL: true,
  canWriteACL: false, // Cannot write ACL/policy
  canViewDNS: true,
  canWriteDNS: false, // Cannot write DNS/network config
  canManageAuthKeys: true,
  canManageAPIKeys: true,
  canViewLogs: true,
  canViewSettings: true,
  canViewServices: true,
  canWriteServices: false, // Read-only
  canViewDebug: false,
};

const NO_ACCESS: Permissions = {
  canAccessAdmin: false,
  canViewMachines: false,
  canWriteMachines: false,
  canViewUsers: false,
  canWriteUsers: false,
  canViewACL: false,
  canWriteACL: false,
  canViewDNS: false,
  canWriteDNS: false,
  canManageAuthKeys: false,
  canManageAPIKeys: false,
  canViewLogs: false,
  canViewSettings: false,
  canViewServices: false,
  canWriteServices: false,
  canViewDebug: false,
};

export function getPermissions(role: string | undefined): Permissions {
  switch (role) {
    case "admin":
      return ADMIN;
    case "network_admin":
      return NETWORK_ADMIN;
    case "it_admin":
      return IT_ADMIN;
    default:
      return NO_ACCESS;
  }
}
