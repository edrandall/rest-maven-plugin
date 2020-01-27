
/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package com.github.cjnygard.mvn.rest;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.ProtocolException;
import java.net.URI;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.charset.UnsupportedCharsetException;
import java.util.Map;
import java.util.Properties;
import java.util.stream.Collectors;

import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.UriBuilder;

import org.apache.commons.io.IOUtils;
import org.apache.commons.text.StringSubstitutor;

import org.apache.maven.execution.MavenSession;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecution;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.descriptor.PluginDescriptor;
import org.apache.maven.plugins.annotations.Component;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.project.MavenProject;
import org.apache.maven.project.MavenProjectHelper;

import org.apache.maven.settings.Settings;
import org.apache.maven.settings.Server;
import org.apache.maven.settings.crypto.DefaultSettingsDecryptionRequest;
import org.apache.maven.settings.crypto.SettingsDecrypter;
import org.apache.maven.settings.crypto.SettingsDecryptionRequest;
import org.apache.maven.settings.crypto.SettingsDecryptionResult;


/**
 * Make a REST request, using GET or POST methods.
 * GET makes a simple HTTP query.
 * POST sends an HTML form or JSON request.
 * Response is saved to a file.
 *
 * This plugin provides an interface to REST services via HTTP,
 * retrieving and storing the response.
 */
@Mojo( name = "rest-request", defaultPhase=LifecyclePhase.DEPLOY, threadSafe=true)
public class Plugin extends AbstractMojo
{

    public class ErrorInfo
    {
        private final int errorCode;
        private final String message;

        public ErrorInfo( int code, String msg )
        {
            errorCode = code;
            message = msg;
        }

        public boolean isOK() {
            return(errorCode >= 200 && errorCode <= 299);
        }

        public int getCode() {
            return errorCode;
        }

        public String getMessage() {
            return message;
        }

        @Override
        public String toString()
        {
            StringBuilder sb = new StringBuilder();
            sb.append( " [" ).append( errorCode ).append( ":" ).append( message ).append( "]" );
            return sb.toString();
        }
    }

    private static final String UTF8 = StandardCharsets.UTF_8.name();

    @Parameter( defaultValue = "${session}", readonly = true )
    private MavenSession session;

    @Parameter( defaultValue = "${project}", readonly = true )
    private MavenProject project;

    @Parameter( defaultValue = "${mojoExecution}", readonly = true )
    private MojoExecution mojo;

    @Parameter( defaultValue = "${plugin}", readonly = true ) // Maven 3 only
    private PluginDescriptor plugin;

    @Parameter( defaultValue = "${settings}", readonly = true )
    private Settings settings;

    @Component
    private SettingsDecrypter settingsDecrypter;

    @Component
    private MavenProjectHelper projectHelper;

    /**
     * Base directory for build.
     *
     * Currently unused, but exists for possible future use.
     *
     * Default <code>${project.basedir}</code>
     *
     */
    @Parameter( defaultValue = "${project.basedir}", readonly = true )
    private File basedir;

    /**
     * Base directory for target.
     *
     * Currently unused, but exists for possible future use.
     *
     * Default <code>${project.build.directory}</code>
     *
     */
    @Parameter( defaultValue = "${project.build.directory}", readonly = true )
    private File target;

    /**
     * A server Id corresponding to an entry in the settings.xml file, to obtain credentials.
     *
     * Decrypted credentials will be placed in properties <code>{serverId}.username</code>
     * and <code>{serverid}.password</code> and may then be referenced in headers and
     * queryParams.
     */
    @Parameter( property = "serverId" )
    private String serverId;

    /**
     * A URL path to the base of the REST request resource.
     *
     * This URL path is the base path, and can be used with multiple instances
     * (executions) in combination with the <code>resource</code> element to
     * specify different URL resources with a common base URL.
     *
     */
    @Parameter( property = "endpoint" )
    private URI endpoint;

    /**
     * A resource path added to the endpoint URL to access the REST resource.
     *
     * The <code>resource</code> path will be concatenated onto the
     * <code>endpoint</code> URL to create the full resource path.
     *
     * Query parameters can be added to the URL <code>resource</code> but the
     * preference is to use the <code>queryParams</code> map to add parameters
     * to the URL.
     */
    @Parameter( property = "resource" )
    private String resource;

    /**
     * The method to use for the REST request.
     *
     * The REST request method can be configured via the <code>method</code>
     * tag. Currently only the <code>POST</code> and <code>GET</code> requests
     * are fully tested and supported. Other methods requiring data upload
     * (<code>PUT</code>, <code>PATCH</code>) should be supported identically to
     * the <code>POST</code> request, but have not been tested.
     *
     * If <code>GET</code> is used, the code will upload a file if the
     * <code>fileset<code> is defined when making the <code>GET</code> request.
     *
     * Defaults to <code>POST</code>
     *
     */
    @Parameter( property = "method" )
    private String method = "POST";


    /**
     * Path where REST response result file is stored.
     *
     * Defaults to <code>${project.build.directory}</code>
     *
     */
    @Parameter( defaultValue = "${project.build.directory}", property = "outputDir" )
    private File outputDir;

    /**
     * Filename where REST response file is stored.
     *
     * Defaults to <code>rest.file</code>
     *
     */
    @Parameter( defaultValue = "rest-response.out", property = "outputFilename" )
    private String outputFilename;

    /**
     * A <code>map</code> of query parameters to add to the REST request URL.
     *
     * The <code>queryParams</code> element will provide a way to add multiple
     * query params to the final REST URL.
     */
    @Parameter( property = "queryParams" )
    private Map<String, String> queryParams;

    /**
     * A <code>map</code> of form fields to POST to the REST request URL.
     */
    @Parameter( property = "formFields" )
    private Map<String, String> formFields;

    /**
     * A <code>map</code> of query headers to add to the REST request.
     *
     * The <code>headers</code> element will provide a way to add multiple
     * header elements to the final REST request.
     */
    @Parameter( property = "headers" )
    private Map<String, String> headers;

    /**
     * The type of the data sent by the REST request.
     *
     * Default: <code>MediaType.APPLICATION_FORM_URLENCODED</code>
     *
     * <pre>
     *     &lt;requestType&gt;application/x-www-form-urlencoded&lt;/requestType&gt;
     * </pre>
     */
    @Parameter
    private String requestType = MediaType.APPLICATION_FORM_URLENCODED;

    /**
     * The type of data expected from the REST response.
     *
     * Default: <code>MediaType.APPLICATION_JSON</code>
     *
     * <pre>
     *     &lt;responseType&gt;application/json&lt;/responseType&gt;
     * </pre>
     */
    @Parameter
    private String responseType = MediaType.APPLICATION_JSON;


    /**
     * Note that the execution parameter will be injected ONLY if this plugin is
     * executed as part of a maven standard lifecycle - as opposed to directly
     * invoked with a direct invocation. When firing this mojo directly (i.e.
     * {@code mvn rest:something} ), the {@code execution} object will not be
     * injected.
     */
    @Parameter( defaultValue = "${mojoExecution}", readonly = true )
    private MojoExecution execution;

    private <T> T getInjectedObject( final T objectOrNull, final String objectName )
    {
        if ( objectOrNull == null )
        {
            getLog().error(
                    String.format( "Found null [%s]: Maven @Component injection was not done properly.", objectName ) );
        }

        return objectOrNull;
    }


    /**
     * @return The active MavenProject.
     */
    protected final MavenProject getProject()
    {
        return getInjectedObject( project, "project" );
    }


    /**
     * @return The active MojoExecution.
     */
    public MojoExecution getExecution()
    {
        return getInjectedObject( execution, "execution" );
    }

    protected void pipeToFile( InputStream stream, File outputFile ) throws IOException
    {
        getLog().info( String.format( "Writing file [%s]", outputFile.getCanonicalPath() ) );
        OutputStream outStream = new FileOutputStream( outputFile );

        byte[] buffer = new byte[8 * 1024];
        int bytesRead;
        while ( (bytesRead = stream.read( buffer )) != -1 )
        {
            outStream.write( buffer, 0, bytesRead );
        }
        IOUtils.closeQuietly( stream );
        IOUtils.closeQuietly( outStream );
    }


    protected boolean validateOutputDir() throws MojoExecutionException
    {
        try
        {
            if ( null == getOutputDir() )
            {
                outputDir = getProject().getBasedir();
            }

            if ( !outputDir.isDirectory() )
            {
                if ( outputDir.isFile() )
                {
                    getLog().error( String.format( "Error: OutputDir [%s] is a file", outputDir.getCanonicalPath() ) );
                }
                else
                {
                    if ( !outputDir.mkdirs() )
                    {
                        getLog().error(
                                String.format( "Error: Unable to create path[%s]", outputDir.getCanonicalPath() ) );
                    }
                }
            }
        }
        catch ( IOException ex )
        {
            getLog().error( String.format( "IOException: [%s]", ex.toString() ) );
            throw new MojoExecutionException(
                    String.format( "Unable to create destination dir [%s]: [%s]", outputDir.toString(),
                            ex.toString() ) );
        }
        return true;
    }


    /**
     * Provides access to server credentials encrypted within settings.xml.
     */
    private Server decryptServerCredentials(String serverId) throws MojoExecutionException {
        SettingsDecryptionRequest request = new DefaultSettingsDecryptionRequest( findServer(serverId) );
        SettingsDecryptionResult result = settingsDecrypter.decrypt(request);
        return result.getServer();
    }

    /**
     * Find the Server for given serverId in the settings config.
     * @param serverId the serverId to find
     * @return the Server
     * @throws MojoExecutionException if serverId is not found
     */
    private Server findServer(String serverId) throws MojoExecutionException {
        for (Server s : settings.getServers()) {
            if (s.getId().equals(serverId)) {
                return( s );
            }
        }
        throw new MojoExecutionException("serverId not found in settings: " + serverId);
    }

    /**
     * Main plugin execution method.
     */
    @Override
    public void execute() throws MojoExecutionException
    {
        validateOutputDir();
        getLog().debug( String.format( "Output dir: [%s]", getOutputDir().toString() ) );

        Properties mvnProps = project.getProperties();
        if (serverId != null && serverId.length() > 0) {
            Server serverCreds = decryptServerCredentials(serverId);
            getLog().debug( String.format( "Setting properties for serverId: [%s] credentials", serverId ) );
            mvnProps.put("server.username", serverCreds.getUsername());
            getLog().debug( String.format( "Set property [server.username]=[%s]", serverCreds.getUsername() ) );
            mvnProps.put("server.password", serverCreds.getPassword());
            getLog().debug( String.format( "Set property [server.password]=[%s]", serverCreds.getPassword().replaceAll(".", "*") ) );
        }
        getLog().debug("mvnprops="+mvnProps);

        UriBuilder uriBuilder = UriBuilder.fromUri( getEndpoint() );
        getLog().debug( String.format( "Endpoint URI [%s]", uriBuilder ) );

        if ( null != getResource() ) {
            getLog().debug( String.format( "Appending resource [%s]", getResource() ) );
            uriBuilder.path( getResource() );
            getLog().debug( String.format( "Resource URI [%s]", uriBuilder ) );
        }

        // Load up the query parameters, if set
        addQueryParams(uriBuilder, mvnProps);
        getLog().debug( String.format( "Query URI [%s]", uriBuilder ) );

        // Prepare the HTTP connection.  Set the request method and headers.
        HttpURLConnection connection = prepareConnection(uriBuilder, mvnProps);

        // Send the request body for POST, PUT
        writeRequestBody(connection, mvnProps);

        ErrorInfo status = processResponse(connection);
        getLog().info("Finished - status="+status);
    }

    /**
     * Prepare to make a connection to the given URI.
     * @param uriBuilder the built URI
     * @param mvnProps Properties to be substitutes in Headers.
     * @return the HttpURLConnection
     * @throws MojoExecutionException in case of any failure
     */
    private HttpURLConnection prepareConnection(UriBuilder uriBuilder, Properties mvnProps) throws MojoExecutionException {
        try {
            URL url = uriBuilder.build().toURL();
            getLog().info( String.format( "Request URL: [%s %s]", getMethod(), url) );
            HttpURLConnection connection = (HttpURLConnection)url.openConnection();
            connection.setRequestMethod( getMethod() );

            // set the request headers
            addHeaders(connection, mvnProps);

            return connection;

        } catch (MalformedURLException mux) {
            throw new MojoExecutionException("Malformed endpoint/resource path:"+endpoint, mux);
        } catch (ProtocolException px) {
            throw new MojoExecutionException("Invalid request method:"+method+" for endpoint:"+endpoint, px);
        } catch (IOException iox) {
            throw new MojoExecutionException("Unable to openConnection to endpoint:"+endpoint, iox);
        }
    }

    /**
     * Set the connection Content-Type, Aaccept and any additional headers.
     * Replace any placeholders in the header values by mvnProps.
     * @param connection the URLConnection

     * @param mvnProps property placeholders to replace
     */
    private void addHeaders(URLConnection connection, Properties mvnProps) {
       addHeader( connection, HttpHeaders.CONTENT_TYPE, getRequestType());
       addHeader( connection, HttpHeaders.ACCEPT, getResponseType());

       Map<String,String> headers = getHeaders();
       if ( headers != null ) {
           for ( Map.Entry<String,String> e :headers.entrySet() ) {
               String key = e.getKey();
               String value = StringSubstitutor.replace(e.getValue(), mvnProps);
               if (value == null) {
                   getLog().warn( String.format("header [%s] has NULL value after placeholder substitution - try using $${..}", key));
                   value = "";
                }
                addHeader( connection, key, value);
            }
        }
    }

    /**
     * Set a single header
     * @param connection to set the header on
     * @param name header name
     * @param value header value
     */
    private void addHeader(URLConnection connection, String name, String value) {
        connection.setRequestProperty(name, value);
        getLog().debug( String.format( "Added header: [%s:%s]", name, value ) );
    }

    /**
     * Append the query parameters, if any.
     * @param endpoint the URI
     * @param mvnProps Properties for substitution into query parameter values
     * @return updated endpoint URI with query appended
     */
    private void addQueryParams(UriBuilder uriBuilder, Properties mvnProps) {
        // Load up the query parameters if they exist
        if ( !isEmpty(queryParams) ) {
            for ( Map.Entry<String,String> e : queryParams.entrySet() )
            {
                try {
                    String key = URLEncoder.encode(e.getKey(), UTF8);
                    String value = StringSubstitutor.replace(e.getValue(), mvnProps);
                    if (value == null) {
                        getLog().warn( String.format("queryParam [%s] has NULL value after placeholder substitution - try using $${..}", key));
                        value = "";
                    }
                    value = URLEncoder.encode(value, UTF8);
                    uriBuilder.queryParam(key, value);
                    getLog().debug( String.format( "Added query param [%s:%s]", key, value ) );
                } catch (UnsupportedEncodingException ex) {
                    // UTF8 unsupported?  Never going to happen.
                    throw new UnsupportedCharsetException("Unable to encode UTF8!");
                }
            }
            getLog().debug( String.format( "URI with query: [%s]", uriBuilder ) );
        }
    }

    /**
     * For a POST request, write the body containing the form fields.
     * @param connection HttpURLConnection to write the body to
     * @param mvnProps Properties for substitution into form field values
     * @throws MojoExecutionException in case of any failure
     */
    private void writeRequestBody(HttpURLConnection connection, Properties mvnProps) throws MojoExecutionException {
        if (method.equalsIgnoreCase("POST")) {
            if (!isEmpty(formFields)) {
                getLog().debug( String.format( "%s request with %d formFields", method, formFields.size()) );
                String body = prepareRequestBody(mvnProps);
                connection.setDoOutput(true);
                try {
                    try(OutputStream out = connection.getOutputStream()) {
                        byte[] data = body.getBytes(UTF8);
                        out.write(data, 0, data.length);
                    }
                } catch (IOException iox) {
                    throw new MojoExecutionException("Unable to write body to endpoint:"+connection.getURL(), iox);
                }
            }
        }
    }


    /**
     * Create a body containing encoded form fields for the request.
     * @param mvnProps Properties for substitution into form field values
     */
    private String prepareRequestBody(Properties mvnProps) {
        Map<String,String> formFields = getFormFields();
        if ( !isEmpty(formFields) ) {
            StringWriter sw = new StringWriter();
            try(PrintWriter pw = new PrintWriter(sw)) {
                boolean first = true;
                for (Map.Entry<String,String> e : formFields.entrySet() )
                {
                    try {
                        String key = URLEncoder.encode(e.getKey(), UTF8);
                        String value = StringSubstitutor.replace(e.getValue(), mvnProps);
                        if (value == null) {
                            getLog().warn( String.format("formField [%s] has NULL value after placeholder substitution - try using $${..}", key));
                            value = "";
                        }
                        value = URLEncoder.encode(value, UTF8);
                        if (first) {
                            first = false;
                        } else {
                            pw.print('&');
                        }
                        pw.print(key);
                        pw.print('=');
                        pw.print(value);
                        getLog().debug( String.format( "Added form field: [%s:%s]", key, value ) );
                    } catch (UnsupportedEncodingException ex) {
                        // UTF8 unsupported?  Never going to happen.
                        throw new UnsupportedCharsetException("Unable to encode UTF8!");
                    }
                }
            }
            return sw.toString();
        }
        return null;
    }

    /**
     * Read the HTTP status and save the response body into a file.
     * @param connection HttpUrlConnection to read from
     * @return ErrorInfo encapsulating the status
     * @throws MojoExecutionException
     */
    private ErrorInfo processResponse( HttpURLConnection connection ) throws MojoExecutionException
    {
        try {
            ErrorInfo status = new ErrorInfo(connection.getResponseCode(), connection.getResponseMessage());
            if ( status.isOK() ) {
                File of = new File( getOutputDir(), getOutputFilename() );
                try {
                    pipeToFile( connection.getInputStream(), of );
                }
                catch ( IOException fx ) {
                    throw new MojoExecutionException( String.format( "IOException writing response body to file:[%s]", of ), fx );
                }
            } else {
                getLog().warn( String.format( "Error: [%s]", status ) );
                BufferedReader br = new BufferedReader( new InputStreamReader( connection.getErrorStream() ) );
                String errorResponse = br.lines().collect( Collectors.joining() );
                getLog().warn( errorResponse );
            }
            return status;

        } catch (IOException cx) {
            throw new MojoExecutionException( String.format("IOException from connection:[%s]", connection.getURL()), cx);
        }
    }


    /**
     * Null-safe check if the specified map is empty.
     */
    private static boolean isEmpty(final Map<?,?> map) {
        return map == null || map.isEmpty();
    }

    /**
     * @return the endpoint
     */
    public URI getEndpoint()
    {
        return endpoint;
    }

    /**
     * @return the resource
     */
    public String getResource()
    {
        return resource;
    }

    /**
     * @return the outputDir
     */
    public File getOutputDir()
    {
        return outputDir;
    }

    /**
     * @return the outputFilename
     */
    public String getOutputFilename()
    {
        return outputFilename;
    }

    /**
     * @return the requestType
     */
    public String getRequestType()
    {
        return requestType;
    }

    /**
     * @return the responseType
     */
    public String getResponseType()
    {
        return responseType;
    }

    /**
     * @return the queryParams
     */
    public Map<String, String> getQueryParams()
    {
        return queryParams;
    }

    /**
     * @return the headers
     */
    public Map<String, String> getHeaders()
    {
        return headers;
    }

    /**
     * @return the formFieldss
     */
    public Map<String, String> getFormFields()
    {
        return formFields;
    }

    /**
     * @return the basedir
     */
    public File getBasedir()
    {
        return basedir;
    }

    /**
     * @return the target
     */
    public File getTarget()
    {
        return target;
    }

    /**
     * @return the projectHelper
     */
    public MavenProjectHelper getProjectHelper()
    {
        return projectHelper;
    }

    /**
     * @return the method
     */
    public String getMethod()
    {
        return method;
    }

    /**
     * @param method
     *            the method to set
     */
    public void setMethod( String method )
    {
        this.method = method;
    }

}
