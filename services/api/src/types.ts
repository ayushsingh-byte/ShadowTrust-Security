export type Role = 'admin' | 'analyst' | 'viewer';

export type AuthContext = {
  userId: string;
  role: Role;
  email?: string;
};

export type NodeConfig = {
  nodeId: string;
  name?: string;
  sqlitePath: string;
  region?: string;
};
