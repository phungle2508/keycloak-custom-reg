package com.example.kc.customreg;

import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.*;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.common.util.Time;
import org.keycloak.credential.hash.PasswordHashProvider;

import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import java.util.*;

/**
 * Custom registration & password reset over phone OTP.
 * - Username = phone number
 * - Email is optional; NOT required to be verified for login
 * - User can verify email later on demand
 */
@Path("/")
@Consumes(MediaType.APPLICATION_JSON)
@Produces(MediaType.APPLICATION_JSON)
public class CustomRegResource {

    private final KeycloakSession session;

    public CustomRegResource(KeycloakSession session) {
        this.session = session;
    }

    /* ======= Registration ======= */

    public record SendReq(String phone) {
    }

    public record SendRes(String txnId, long expiresIn) {
    }

    public record VerifyReq(String txnId, String code) {
    }

    public record VerifyRes(String regToken, long expiresIn) {
    }

    public record CompleteReq(String regToken, String email, String firstName, String lastName, String password) {
    }

    @POST
    @Path("send-otp")
    public Response sendOtp(SendReq req) {
        String phone = Util.normalizePhone(req.phone());
        if (phone == null)
            return Response.status(400).entity(Map.of("error", "bad_phone")).build();

        String code = Util.generate6();
        long ttlSec = Util.realmIntAttr(session, "sms.otp.ttlSeconds", 90);
        String txnId = UUID.randomUUID().toString();

        OtpStore.putTxn(session, txnId, new OtpRecord(phone, code, Time.currentTime() + (int) ttlSec));
        boolean ok = SmsGateway.send(session, phone, "Ma OTP: " + code + " (het han " + ttlSec + "s)");
        if (!ok)
            return Response.serverError().entity(Map.of("error", "sms_failed")).build();

        return Response.ok(new SendRes(txnId, ttlSec)).build();
    }

    @POST
    @Path("verify-otp")
    public Response verifyOtp(VerifyReq req) {
        OtpRecord rec = OtpStore.getTxn(session, req.txnId());
        if (rec == null || !Objects.equals(rec.code(), req.code()) || rec.isExpired()) {
            return Response.status(400).entity(Map.of("error", "invalid_code")).build();
        }
        OtpStore.removeTxn(session, req.txnId());

        String regToken = JwtUtil.issue(session, Map.of(
                "typ", "reg",
                "phone", rec.phone()), 300); // 5 minutes
        return Response.ok(new VerifyRes(regToken, 300)).build();
    }

    @POST
    @Path("complete")
    public Response complete(CompleteReq req) {
        Map<String, Object> claims = JwtUtil.verifyRequire(session, req.regToken(), "typ", "reg");
        String phone = (String) claims.get("phone");
        if (phone == null)
            return Response.status(400).entity(Map.of("error", "no_phone")).build();

        RealmModel realm = session.getContext().getRealm();

        // Prevent duplicates by phone_number
        boolean exists = session.users()
                .searchForUserByUserAttributeStream(realm, "phone_number", phone).findAny().isPresent();
        if (exists)
            return Response.status(409).entity(Map.of("error", "phone_exists")).build();

        // Create user with username = phone
        UserModel user = session.users().addUser(realm, KeycloakModelUtils.generateId());
        user.setUsername(phone);
        user.setEnabled(true);

        if (req.email() != null && !req.email().isBlank()) {
            user.setEmail(req.email());
            // Cho phép đăng nhập ngay cả khi chưa xác minh email:
            user.setEmailVerified(false);
            // KHÔNG ép required action VERIFY_EMAIL — user có thể xác minh sau
        }

        if (req.firstName() != null)
            user.setFirstName(req.firstName());
        if (req.lastName() != null)
            user.setLastName(req.lastName());

        user.setSingleAttribute("phone_number", phone);
        user.setSingleAttribute("phone_verified", "true"); // vì đã OTP

        // Set password with current realm policy (Keycloak 26.x)
        PasswordPolicy policy = realm.getPasswordPolicy();
        PasswordHashProvider hashProvider = session.getProvider(PasswordHashProvider.class, policy.getHashAlgorithm());
        PasswordCredentialModel hashedCredential = hashProvider.encodedCredential(req.password(),
                policy.getHashIterations());
        user.credentialManager().updateStoredCredential(hashedCredential);

        // Emit register event
        new EventBuilder(realm, session, session.getContext().getConnection())
                .event(EventType.REGISTER)
                .user(user)
                .detail("method", "custom-http")
                .success();

        return Response.status(201).entity(Map.of("userId", user.getId())).build();
    }

    /* ======= Password reset (via phone OTP) ======= */

    public record ResetReq(String phone) {
    }

    public record ResetVerifyReq(String txnId, String code) {
    }

    public record ResetVerifyRes(String resetToken, long expiresIn) {
    }

    public record ResetCompleteReq(String resetToken, String newPassword) {
    }

    @POST
    @Path("reset/request")
    public Response resetRequest(ResetReq req) {
        String phone = Util.normalizePhone(req.phone());
        if (phone == null)
            return Response.status(400).entity(Map.of("error", "bad_phone")).build();

        RealmModel realm = session.getContext().getRealm();
        Optional<UserModel> userOpt = session.users()
                .searchForUserByUserAttributeStream(realm, "phone_number", phone).findAny();

        String txnId = UUID.randomUUID().toString();
        String code = Util.generate6();
        long ttlSec = Util.realmIntAttr(session, "sms.otp.ttlSeconds", 90);

        userOpt.ifPresent(u -> OtpStore.putReset(session, txnId,
                new OtpRecord(u.getId(), code, Time.currentTime() + (int) ttlSec)));
        userOpt.ifPresent(u -> SmsGateway.send(session, phone, "OTP reset: " + code));

        // Luôn trả về txnId (tránh lộ user tồn tại hay không)
        return Response.ok(Map.of("txnId", txnId, "expiresIn", ttlSec)).build();
    }

    @POST
    @Path("reset/verify")
    public Response resetVerify(ResetVerifyReq req) {
        OtpRecord rec = OtpStore.getReset(session, req.txnId());
        if (rec == null || !Objects.equals(rec.code(), req.code()) || rec.isExpired()) {
            return Response.status(400).entity(Map.of("error", "invalid_code")).build();
        }
        OtpStore.removeReset(session, req.txnId());

        String resetToken = JwtUtil.issue(session, Map.of(
                "typ", "reset",
                // reuse OtpRecord.phone() field to carry userId in reset store (như comment
                // gốc)
                "userId", rec.phone()), 600); // 10 minutes
        return Response.ok(new ResetVerifyRes(resetToken, 600)).build();
    }

    @POST
    @Path("reset/complete")
    public Response resetComplete(ResetCompleteReq req) {
        Map<String, Object> claims = JwtUtil.verifyRequire(session, req.resetToken(), "typ", "reset");
        String userId = (String) claims.get("userId");
        if (userId == null)
            return Response.status(400).entity(Map.of("error", "no_user")).build();

        RealmModel realm = session.getContext().getRealm();
        UserModel user = session.users().getUserById(realm, userId);
        if (user == null)
            return Response.status(404).build();

        // Set new password
        PasswordPolicy policy = realm.getPasswordPolicy();
        PasswordHashProvider hashProvider = session.getProvider(PasswordHashProvider.class, policy.getHashAlgorithm());
        PasswordCredentialModel hashedCredential = hashProvider.encodedCredential(req.newPassword(),
                policy.getHashIterations());
        user.credentialManager().updateStoredCredential(hashedCredential);

        // Revoke online/offline sessions
        session.sessions().getUserSessionsStream(realm, user)
                .forEach(s -> session.sessions().removeUserSession(realm, s));
        session.sessions().getOfflineUserSessionsStream(realm, user)
                .forEach(s -> session.sessions().removeUserSession(realm, s));

        // Emit event
        new EventBuilder(realm, session, session.getContext().getConnection())
                .event(EventType.RESET_PASSWORD)
                .user(user)
                .success();

        return Response.ok(Map.of("status", "ok")).build();
    }
}
