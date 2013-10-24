package org.osiam.storage.entities.extension

import org.osiam.storage.entities.UserEntity
import spock.lang.Specification

/**
 * Created with IntelliJ IDEA.
 * User: Igor
 * Date: 24.10.13
 * Time: 13:34
 * To change this template use File | Settings | File Templates.
 */
class ExtensionFieldValueSpec extends Specification {
    ExtensionFieldValue extFieldValue = new ExtensionFieldValue();

    def "setter and getter for the Id should be present"(){
        def id = 42
        when:
        extFieldValue.setInternalId(id)

        then:
        extFieldValue.getInternalId() == id
    }

    def "setter and getter for the extensionField should be present"(){
        def extensionField = Mock(ExtensionField.class)
        when:
        extFieldValue.setExtensionField(extensionField)

        then:
        extFieldValue.getExtensionField() == extensionField
    }

    def "setter and getter for the userEntity should be present"(){
        def userEntity = Mock(UserEntity.class)
        when:
        extFieldValue.setUserEntity(userEntity)

        then:
        extFieldValue.getUserEntity() == userEntity
    }

    def "setter and getter for the value should be present"(){
        def value = ":-)"
        when:
        extFieldValue.setValue(value)

        then:
        extFieldValue.getValue() == value
    }
}