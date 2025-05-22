/************************************************************************
 *                                                                       *
 *  Signature Service - Support Service Library                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public License   *
 *  License as published by the Free Software Foundation; either         *
 *  version 3 of the License, or any later version.                      *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package se.signatureservice.support.api.v2

import se.signatureservice.configuration.common.InternalErrorException
import se.signatureservice.configuration.common.InvalidArgumentException
import spock.lang.Specification

class UserSpec extends Specification {
    def "test serialization"(){
        setup:
        User user1 = new User(userId: "190101010001")
        User user2 = new User(userId: "190101010002", role: "tester")
        User user3 = new User(userId: "190101010003", role: "tester", userAttributes: [
                new Attribute(key: "displayName", value: "Johnny Cash"),
                new Attribute(key: "securityLevel", value: "TOP_SECRET")
        ])

        when:
        User restoredUser1 = deserializeUser(serializeUser(user1))
        User restoredUser2 = deserializeUser(serializeUser(user2))
        User restoredUser3 = deserializeUser(serializeUser(user3))

        then:
        restoredUser1.userId == "190101010001"
        restoredUser1.role == null
        restoredUser1.userAttributes == null

        restoredUser2.userId == "190101010002"
        restoredUser2.role == "tester"
        restoredUser2.userAttributes == null

        restoredUser3.userId == "190101010003"
        restoredUser3.role == "tester"
        restoredUser3.userAttributes != null
        restoredUser3.userAttributes.size() == 2
        restoredUser3.userAttributes[0].key == "displayName"
        restoredUser3.userAttributes[0].value == "Johnny Cash"
        restoredUser3.userAttributes[1].key == "securityLevel"
        restoredUser3.userAttributes[1].value == "TOP_SECRET"
    }

    private static byte[] serializeUser(User user) throws IOException, InvalidArgumentException, InternalErrorException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream()
        ObjectOutputStream oos = new ObjectOutputStream(baos)
        oos.writeObject(user)
        return baos.toByteArray()
    }

    private static User deserializeUser(byte[] serializedUser) throws InvalidArgumentException, IOException, InternalErrorException, ClassNotFoundException {
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(serializedUser)){
            protected Class<?> resolveClass(ObjectStreamClass objectStreamClass) throws IOException, ClassNotFoundException {
                return Class.forName(objectStreamClass.getName(), true, V2SupportServiceAPI.class.getClassLoader());
            }
        }
        return (User)ois.readObject()
    }
}
