/* This file is part of the University of Cambridge Web Authentication
 * System Java Toolkit
 *
 * Copyright 2005,2014 University of Cambridge
 *
 * This toolkit is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * The toolkit is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this toolkit; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
 * USA
 *
 * $Id: WebauthException.java,v 1.2 2005/03/30 13:17:06 jw35 Exp $
 *
 */

package uk.ac.cam.ucs.webauth;

/**
 * Represents exception conditions within the WebAuth system
 * 
 * @version $Revision: 1.2 $ $Date: 2005/03/30 13:17:06 $
 */
public class WebauthException extends Exception {

  private static final long serialVersionUID = -2026879764875255843L;
  /** The http status that caused this exception. 0 means not set. */
  int status = 0;

  /**
   * Default constrictor
   */
  @SuppressWarnings("unused")
  private WebauthException() {
    super();
  }

  /**
   * Alternate constructor
   * 
   * @param desc a string description of the exception
   */
  public WebauthException(String desc) {
    super(desc);
  }

  /**
   * Alternate constructor
   * 
   * @param desc a string description of the exception
   */
  public WebauthException(String desc, Throwable cause) {
    super(desc, cause);
  }

  /**
   * Constructor
   * 
   * @param desc a string description of the exception
   * @param status The http status code from Raven.
   */
  public WebauthException(String desc, int status) {
    super(desc);

    assert (status != 200);

    this.status = status;
  }

  /**
   * Constructor
   * 
   * @param desc a string description of the exception
   * @param status The http status code from Raven.
   * @param cause The exception that caused this one.
   */
  public WebauthException(String desc, int status, Throwable cause) {
    super(desc, cause);

    assert (status != 200);

    this.status = status;
  }

  /**
   * Gets the status that caused this exception.
   * 
   * Typically they are http status codes. Check WebauthResponse for details. 200 means every went
   * ok and thus should not be returned by this method if it is constructed well.
   * 
   * @return the status
   */
  public int getStatus() {
    return status;
  }

}
