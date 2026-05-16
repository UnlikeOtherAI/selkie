import { NavLink, useNavigate } from "react-router-dom";
import type { JWTClaims } from "../lib/auth";
import { removeToken } from "../lib/auth";

interface NavItem {
  path: string;
  label: string;
  icon: React.ReactNode;
  end?: boolean;
}

const navItems: NavItem[] = [
  {
    path: "/admin",
    label: "Overview",
    end: true,
    icon: (
      <svg className="w-4 h-4 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="1.8">
        <rect x="3" y="3" width="7" height="7" rx="1" />
        <rect x="14" y="3" width="7" height="7" rx="1" />
        <rect x="3" y="14" width="7" height="7" rx="1" />
        <rect x="14" y="14" width="7" height="7" rx="1" />
      </svg>
    ),
  },
  {
    path: "/admin/devices",
    label: "Devices",
    icon: (
      <svg className="w-4 h-4 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="1.8">
        <rect x="2" y="6" width="20" height="12" rx="2" />
        <path d="M8 12h8M12 9v6" />
      </svg>
    ),
  },
  {
    path: "/admin/sessions",
    label: "Sessions",
    icon: (
      <svg className="w-4 h-4 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="1.8">
        <path d="M9 12l2 2 4-4M7.835 4.697a3.42 3.42 0 001.946-.806 3.42 3.42 0 014.438 0 3.42 3.42 0 001.946.806 3.42 3.42 0 013.138 3.138 3.42 3.42 0 00.806 1.946 3.42 3.42 0 010 4.438 3.42 3.42 0 00-.806 1.946 3.42 3.42 0 01-3.138 3.138 3.42 3.42 0 00-1.946.806 3.42 3.42 0 01-4.438 0 3.42 3.42 0 00-1.946-.806 3.42 3.42 0 01-3.138-3.138 3.42 3.42 0 00-.806-1.946 3.42 3.42 0 010-4.438 3.42 3.42 0 00.806-1.946 3.42 3.42 0 013.138-3.138z" />
      </svg>
    ),
  },
  {
    path: "/admin/services",
    label: "Services",
    icon: (
      <svg className="w-4 h-4 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="1.8">
        <path d="M5 12h14M12 5l7 7-7 7" />
      </svg>
    ),
  },
];

const opsItems: NavItem[] = [
  {
    path: "/admin/relay",
    label: "Relay",
    icon: (
      <svg className="w-4 h-4 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="1.8">
        <path d="M8.684 13.342C8.886 12.938 9 12.482 9 12c0-.482-.114-.938-.316-1.342m0 2.684a3 3 0 110-2.684m0 2.684l6.632 3.316m-6.632-6l6.632-3.316m0 0a3 3 0 105.367-2.684 3 3 0 00-5.367 2.684zm0 9.316a3 3 0 105.368 2.684 3 3 0 00-5.368-2.684z" />
      </svg>
    ),
  },
  {
    path: "/admin/system",
    label: "System",
    icon: (
      <svg className="w-4 h-4 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="1.8">
        <path d="M9 3H5a2 2 0 00-2 2v4m6-6h10a2 2 0 012 2v4M9 3v18m0 0h10a2 2 0 002-2V9M9 21H5a2 2 0 01-2-2V9m0 0h18" />
      </svg>
    ),
  },
];

function navLinkCls({ isActive }: { isActive: boolean }) {
  return `flex items-center gap-2.5 px-3 py-2 rounded text-sm transition-colors ${
    isActive
      ? "bg-slate-700/70 text-slate-200"
      : "text-slate-400 hover:bg-slate-700/50 hover:text-slate-200"
  }`;
}

export function Sidebar({ claims }: { claims: JWTClaims | null }) {
  const navigate = useNavigate();

  const handleSignOut = () => {
    removeToken();
    navigate("/login");
  };

  const initial =
    claims?.display_name?.[0]?.toUpperCase() ||
    claims?.email?.[0]?.toUpperCase() ||
    "U";
  const name = claims?.display_name || claims?.email || "User";

  return (
    <aside className="w-56 shrink-0 flex flex-col bg-slate-900 border-r border-slate-800">
      {/* Logo */}
      <div className="h-14 flex items-center px-4 gap-2.5 border-b border-slate-800">
        <img
          src="/assets/icon-1024.png"
          alt="Selkie"
          className="w-7 h-7 rounded-md shrink-0"
        />
        <span className="font-mono text-sm font-medium text-slate-100 tracking-tight">
          selkie
        </span>
      </div>

      {/* Nav */}
      <nav className="flex-1 px-3 py-4 space-y-0.5 overflow-y-auto">
        {navItems.map((item) => (
          <NavLink
            key={item.path}
            to={item.path}
            end={item.end}
            id={`nav-${item.label.toLowerCase()}`}
            className={navLinkCls}
          >
            {item.icon}
            {item.label}
          </NavLink>
        ))}

        <div className="pt-3 pb-1 px-3">
          <span className="text-xs font-medium text-slate-500 uppercase tracking-wider">
            Ops
          </span>
        </div>

        {opsItems.map((item) => (
          <NavLink
            key={item.path}
            to={item.path}
            id={`nav-${item.label.toLowerCase()}`}
            className={navLinkCls}
          >
            {item.icon}
            {item.label}
          </NavLink>
        ))}
      </nav>

      {/* User footer */}
      <div className="border-t border-slate-800 px-4 py-3">
        <div className="flex items-center gap-2.5">
          {claims?.picture ? (
            <img
              id="user-avatar"
              src={claims.picture}
              alt=""
              crossOrigin="anonymous"
              referrerPolicy="no-referrer"
              className="w-7 h-7 rounded-full shrink-0"
            />
          ) : (
            <div className="w-7 h-7 rounded-full bg-indigo-600 flex items-center justify-center text-xs font-semibold text-white shrink-0">
              {initial}
            </div>
          )}
          <div className="min-w-0">
            <p id="user-email" className="text-xs font-medium text-slate-200 truncate">
              {name}
            </p>
            <p className="text-xs text-slate-500 truncate">
              {claims?.is_super ? "owner" : "user"}
            </p>
          </div>
          <button
            onClick={handleSignOut}
            className="ml-auto text-slate-500 hover:text-slate-300 shrink-0"
            title="Sign out"
          >
            <svg
              className="w-4 h-4"
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
              strokeWidth="1.8"
            >
              <path d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" />
            </svg>
          </button>
        </div>
      </div>
    </aside>
  );
}
