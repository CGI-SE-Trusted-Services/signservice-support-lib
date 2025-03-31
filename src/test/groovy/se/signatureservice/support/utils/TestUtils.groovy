package se.signatureservice.support.utils
/**
 * Class containing test utils used in common unit tests.
 *
 * @author Philip Vendil Apr 21, 2012
 */
class TestUtils {

    /**
     * Help method used to serialize and de-serialize and object in order to test that
     * all required fields are stored properly.
     *
     * @param object the object to serialize
     * @return a copy of the object through serialization and de-serialization.
     */
    static Object genSerializedObjectClone(Object object){
        ByteArrayOutputStream baos = new ByteArrayOutputStream()
        ObjectOutputStream oos = new ObjectOutputStream(baos)
        oos.writeObject(object)
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(baos.toByteArray())){
            protected Class<?> resolveClass(ObjectStreamClass objectStreamClass) throws IOException, ClassNotFoundException {
                return Class.forName(objectStreamClass.getName(), true, TestUtils.classLoader);
            }
        };
        return ois.readObject()
    }

    /**
     * Help method to generate a byte array of a given size that
     * contains random data.
     *
     * @param size Size of byte array to generate.
     * @return Byte array of given size filled with random data.
     */
    static byte[] genRandomByteArray(int size) {
        byte[] array = new byte[size]
        new Random().nextBytes(array)
        return array
    }
}
