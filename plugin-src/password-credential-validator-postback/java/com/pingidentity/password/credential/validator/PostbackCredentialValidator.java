package com.pingidentity.password.credential.validator;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.sourceid.saml20.adapter.attribute.AttributeValue;
import org.sourceid.saml20.adapter.conf.Configuration;
import org.sourceid.saml20.adapter.conf.Field;
import org.sourceid.saml20.adapter.gui.TextFieldDescriptor;
import org.sourceid.saml20.adapter.gui.validation.FieldValidator;
import org.sourceid.saml20.adapter.gui.validation.ValidationException;
import org.sourceid.saml20.adapter.gui.validation.impl.RequiredFieldValidator;
import org.sourceid.saml20.adapter.gui.validation.impl.IntegerValidator;
import org.sourceid.saml20.adapter.gui.validation.impl.URLValidator;
import org.sourceid.saml20.adapter.gui.validation.impl.HttpURLValidator;
import org.sourceid.saml20.adapter.gui.validation.impl.HttpsURLValidator;
import org.sourceid.util.log.AttributeMap;

import com.pingidentity.sdk.GuiConfigDescriptor;
import com.pingidentity.sdk.PluginDescriptor;
import com.pingidentity.sdk.password.PasswordCredentialValidator;
import com.pingidentity.sdk.password.PasswordCredentialValidatorAuthnException;
import com.pingidentity.sdk.password.PasswordValidationException;

import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import java.util.regex.Matcher;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import java.net.URI;
import java.net.URISyntaxException;
import java.io.IOException;
import org.apache.http.ParseException;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.cookie.BasicCookieStore;
import org.apache.hc.client5.http.cookie.Cookie;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.CloseableHttpResponse;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.core5.http.ClassicHttpRequest;
import org.apache.hc.core5.http.HttpEntity;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.apache.hc.core5.http.io.support.ClassicRequestBuilder;




public class PostbackCredentialValidator implements PasswordCredentialValidator
{
    private final Log LOG = LogFactory.getLog(PostbackCredentialValidator.class);

    private static final String TYPE = "Postback Credential Validator";
    private static final String TYPE_DESC = "Proof-of-concept PCV to authenticate against an internal web site via form POST";

    private static final String USERFIELD = "Username Field";
    private static final String USERFIELD_DESC = "Enter the name of the HTML form parameter for the username.";
    private static final String PASSFIELD = "Password Field";
    private static final String PASSFIELD_DESC = "Enter the name of the HTML form parameter for the password.";
    private static final String LOGINURL = "Postback URL";
    private static final String LOGINURL_DESC = "Enter the URL to POST against.";
    private static final String CSRFFIELD = "CSRF Token Field";
    private static final String CSRFFIELD_DESC = "Enter the name of the HTML form parameter that should contain the anti-CSRF token. "
        + "Leave blank if the application does not require an anti-CSRF token.";
    private static final String PATTERN = "CSRF Pattern";
    private static final String PATTERN_DESC = "Enter a regular expression to extract Anti-CSRF tokens. "
        + "The first matching group should contain the CSRF token value.";
    private static final String STATUSCODE = "Successful Status Code";
    private static final String STATUSCODE_DESC = "Enter the expected HTTP status code for successful login (typically 301 or 302). "
        + "Responses that do not match this status code will be treated as login failures.";

    // Names for the contract
    private static final String USERNAME_ATTRIBUTE = "username";
    private static final String CSRFTOKEN_ATTRIBUTE = "csrf_token";
    private static final String RESPONSECODE_ATTRIBUTE = "responsecode";

    String userInput = null;
    String passInput = null;
    String csrfInput = null;
    String csrfPattern = null;
    String loginUrl = null;
    String statusCode = null;
    URI parsedLoginUri = null;

    @Override
    public void configure(Configuration configuration)
    {
        userInput = configuration.getFieldValue(USERFIELD);
        passInput = configuration.getFieldValue(PASSFIELD);
        csrfInput = configuration.getFieldValue(CSRFFIELD);
        csrfPattern = configuration.getFieldValue(PATTERN);
        loginUrl  = configuration.getFieldValue(LOGINURL);
        statusCode = configuration.getFieldValue(STATUSCODE);
        try {
            parsedLoginUri = new URI(loginUrl);
        } catch(URISyntaxException e) {
            throw new PasswordValidationException("Invalid login URL.");
        }
    }

    private class PatternFieldValidator implements FieldValidator {
        @Override
        public void validate(Field field) throws ValidationException {
            String s = field.getValue();
            try {
                Pattern pattern = Pattern.compile(s);
            } catch (PatternSyntaxException e) {
                throw new ValidationException(e.getMessage());
            }
        }
    }

    @Override
    public PluginDescriptor getPluginDescriptor()
    {
        // Build field configuration
        RequiredFieldValidator requiredFieldValidator = new RequiredFieldValidator();

        GuiConfigDescriptor guiDescriptor = new GuiConfigDescriptor();
        guiDescriptor.setDescription(TYPE_DESC);

        TextFieldDescriptor userInputDescriptor = new TextFieldDescriptor(USERFIELD, USERFIELD_DESC);
        userInputDescriptor.setDefaultValue("username");
        userInputDescriptor.addValidator(requiredFieldValidator);
        guiDescriptor.addField(userInputDescriptor);

        TextFieldDescriptor passInputDescriptor = new TextFieldDescriptor(PASSFIELD, PASSFIELD_DESC);
        passInputDescriptor.setDefaultValue("password");
        passInputDescriptor.addValidator(requiredFieldValidator);
        guiDescriptor.addField(passInputDescriptor);

        TextFieldDescriptor csrfInputDescriptor = new TextFieldDescriptor(CSRFFIELD, CSRFFIELD_DESC);
        guiDescriptor.addAdvancedField(csrfInputDescriptor);

        TextFieldDescriptor csrfPatternInputDescriptor = new TextFieldDescriptor(PATTERN, PATTERN_DESC);
        csrfPatternInputDescriptor.addValidator(new PatternFieldValidator());
        guiDescriptor.addAdvancedField(csrfPatternInputDescriptor);

        TextFieldDescriptor statusCodeDescriptor = new TextFieldDescriptor(STATUSCODE, STATUSCODE_DESC);
        statusCodeDescriptor.setDefaultValue("301");
        statusCodeDescriptor.addValidator(new IntegerValidator(200,599),true);
        guiDescriptor.addAdvancedField(statusCodeDescriptor);

        TextFieldDescriptor loginUrlDescriptor = new TextFieldDescriptor(LOGINURL, LOGINURL_DESC);
        loginUrlDescriptor.addValidator(new URLValidator(true));
        loginUrlDescriptor.addValidator(requiredFieldValidator);
        guiDescriptor.addField(loginUrlDescriptor);
    
        PluginDescriptor pluginDescriptor = new PluginDescriptor(TYPE, this, guiDescriptor);

        Set<String> contract = new HashSet<String>();
        contract.add(USERNAME_ATTRIBUTE);
        contract.add(CSRFTOKEN_ATTRIBUTE);
        contract.add(RESPONSECODE_ATTRIBUTE);

        pluginDescriptor.setAttributeContractSet(contract);
        pluginDescriptor.setSupportsExtendedContract(false);    //TODO: should this be set to false?

        return pluginDescriptor;
    }




    @Override
    public AttributeMap processPasswordCredential(String username, String password) throws PasswordValidationException
    {
        if (username == null || password == null)
        {
            throw new PasswordValidationException("Unable to validate null credentials.");
        }

        AttributeMap attributeMap = null;
        String htmlBody = null;
        String csrfToken = null;
        int httpStatus = -1;
        BasicCookieStore cookieJar = new BasicCookieStore();

        try {
            // In order to ensure correct deallocation of system resources
            // the user MUST call CloseableHttpResponse#close() from a finally clause.
            try (final CloseableHttpClient httpclient = HttpClients.custom()
                    .setDefaultCookieStore(cookieJar)
                    .disableRedirectHandling()
                    .build()) {

            // Initial GET request to establish session cookies (and possibly extract CSRF token)
            final HttpGet getRequest = new HttpGet(parsedLoginUri);
            try(final CloseableHttpResponse r = httpclient.execute(getRequest)) {

                final HttpEntity entity = r.getEntity();
                try {
                    htmlBody = EntityUtils.toString(entity);
                } catch(Exception e) {
                    throw new PasswordValidationException("Error parsing response from backend authentication server.");
                }
                EntityUtils.consume(entity);
    
                LOG.info("Initial response code for HTTP GET = " + r.getCode());
                LOG.info("GET request returned cookies: ");
                final List<Cookie> cookies = cookieJar.getCookies();
                if (!cookies.isEmpty()) {
                    for (int i=0; i < cookies.size(); i++) {
                        LOG.info(cookies.get(i).toString());
                    }
                }
            }
            LOG.info(htmlBody);

            // Extract CSRF token if necessary:
            if (!csrfPattern.isEmpty()) {
                Pattern p = Pattern.compile(csrfPattern);
                Matcher m = p.matcher(htmlBody);
                if (m.find()) {
                    LOG.info("Found CSRF Token: " + m.group(1));
                    csrfToken = m.group(1);
                } else {
                    LOG.warn("No pattern match found for CSRF token.");
                }
            }
    
            // Second request using POST to perform login
            ClassicRequestBuilder postRequestBuilder = ClassicRequestBuilder.post();
            postRequestBuilder.setUri(parsedLoginUri);
            postRequestBuilder.addParameter(userInput, username);
            postRequestBuilder.addParameter(passInput, password);
            if (!csrfToken.isEmpty()) {
                postRequestBuilder.addParameter(csrfInput, csrfToken);
            }
            ClassicHttpRequest postRequest = postRequestBuilder.build();

            try (final CloseableHttpResponse r2 = httpclient.execute(postRequest)) {
                final HttpEntity entity = r2.getEntity();
                try {
                    htmlBody = EntityUtils.toString(entity);
                } catch(Exception e) {
                    throw new PasswordValidationException("Error parsing response from backend authentication server.");
                }
                httpStatus = r2.getCode();
                EntityUtils.consume(entity);
                LOG.info("POST response code = " + httpStatus);
           }
        }

        if (httpStatus == Integer.parseInt(statusCode)) {
            attributeMap = new AttributeMap();
            attributeMap.put(USERNAME_ATTRIBUTE, new AttributeValue(username));
            attributeMap.put(CSRFTOKEN_ATTRIBUTE, new AttributeValue(csrfToken));
            attributeMap.put(RESPONSECODE_ATTRIBUTE, new AttributeValue(statusCode));
        } else {
            // Authentication failure should return null or an empty map.
            attributeMap = null;
        }
        
        return attributeMap;

      } catch(IOException e) {
            throw new PasswordValidationException("Error connecting to backend authentication server.");
      }
    }
}

