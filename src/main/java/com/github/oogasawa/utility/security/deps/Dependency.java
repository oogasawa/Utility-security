package com.github.oogasawa.utility.security.deps;

/**
 * A Maven artifact at a fixed version, as resolved for one project.
 *
 * @param groupId the Maven groupId
 * @param artifactId the Maven artifactId
 * @param version the resolved version
 */
public record Dependency(String groupId, String artifactId, String version) {

    /** Returns the name OSV uses for a Maven package: {@code groupId:artifactId}. */
    public String osvName() {
        return groupId + ":" + artifactId;
    }

    @Override
    public String toString() {
        return osvName() + ":" + version;
    }
}
