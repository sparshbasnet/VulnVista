import { Navigate } from "react-router-dom";
import AuthShell from "../components/AuthShell";
import ChangePasswordForm from "../components/ChangePasswordForm";
import { useAuth } from "../auth/useAuth";

/**
 * Where an account issued a temporary password lands. It sits outside the app
 * chrome because the backend blocks every other route until the password is the
 * account owner's own.
 */
export default function ForcedPasswordChange() {
  const { user, mustChangePassword, logout } = useAuth();

  if (!user) return <Navigate to="/login" replace />;
  if (!mustChangePassword) return <Navigate to="/" replace />;

  return (
    <AuthShell
      eyebrow="First sign-in"
      title="Choose your password"
      description={`The password on ${user.username} was set by an administrator. Replace it before using the platform.`}
      footer={
        <button type="button" onClick={() => void logout()} className="font-bold text-[#a61b0d] hover:underline">
          Sign out instead
        </button>
      }
    >
      <p className="vv-alert vv-alert-note mb-5">
        Until this is done, the account can reach nothing but this page.
      </p>
      <ChangePasswordForm submitLabel="Set my password" />
    </AuthShell>
  );
}
